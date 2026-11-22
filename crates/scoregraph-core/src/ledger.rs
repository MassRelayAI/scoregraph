//! The ledger: one append-only, hash-chained SQLite table (`ledger/schema.sql`), and the exported `scores.jsonl`.
//!
//! - **SQLite**: chain v2 hashes `canonical(["scoregraph-chain/2", seq, kind, key, prev, body])`, so re-keying, re-kinding or
//!   re-numbering a row breaks it. Triggers refuse UPDATE and DELETE; [`Ledger::verify`] recomputes every hash, so a row edited
//!   behind the triggers' back is found, and every write refuses a broken chain. A v1 ledger (`sha256(prev || body)`) is sealed
//!   on its first v2 write: a `chain-seal` row holds the digest of every v1 row's (seq, kind, key).
//! - **Head anchor**: a truncated tail, or a truncated and re-forged one, still chains by itself. [`Ledger::head`] gives
//!   `{seq, hash}` to commit on the trusted branch; [`Ledger::verify_anchor`] refuses a ledger that no longer holds that row.
//! - **scores.jsonl**: one `score/1` row per line with `prev` = sha-256 of the previous line's bytes. The copy committed on the
//!   trusted branch must be a prefix of the current file ([`anchor`]): history is only ever appended.
use crate::model::{Observation, SCORE_V1};
use crate::util::{canonical, sha256_hex, ZERO_HASH};
use crate::{refused, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{Map, Value};
use std::path::Path;

pub const SCHEMA: &str = include_str!("../../../ledger/schema.sql");

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub seq: i64,
    pub kind: String,
    pub key: String,
    pub body: Value,
}

pub struct Ledger {
    conn: Connection,
}

pub const CHAIN_V: i64 = 2;
pub const HEAD_V1: &str = "ledger-head/1";

fn chain_hash_v1(prev: &str, body: &str) -> String {
    sha256_hex(format!("{prev}{body}").as_bytes())
}

fn chain_hash_v2(seq: i64, kind: &str, key: &str, prev: &str, body: &str) -> String {
    sha256_hex(canonical(&serde_json::json!(["scoregraph-chain/2", seq, kind, key, prev, body])).as_bytes())
}

/// The digest a `chain-seal` row holds: every v1 row's (seq, kind, key, hash).
fn v1_digest(rows: &[(i64, String, String, String)]) -> String {
    sha256_hex(canonical(&serde_json::json!(rows)).as_bytes())
}

/// Bring an older table forward: add `chain_v` (existing rows are v1). Adding a column is not an UPDATE; the triggers allow it.
fn migrate(conn: &Connection) -> Result<()> {
    let has_table: bool = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'entries'", [], |r| r.get::<_, i64>(0))? > 0;
    if has_table {
        let mut st = conn.prepare("PRAGMA table_info(entries)")?;
        let cols: Vec<String> = st.query_map([], |r| r.get::<_, String>(1))?.collect::<std::result::Result<_, _>>()?;
        if !cols.iter().any(|c| c == "chain_v") {
            conn.execute_batch("ALTER TABLE entries ADD COLUMN chain_v INTEGER NOT NULL DEFAULT 1;")?;
        }
    }
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

impl Ledger {
    pub fn open(path: &Path) -> Result<Ledger> {
        let conn = Connection::open(path)?;
        migrate(&conn)?;
        conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('format', 'scoregraph-ledger/1')", [])?;
        Ok(Ledger { conn })
    }

    pub fn in_memory() -> Result<Ledger> {
        let conn = Connection::open_in_memory()?;
        migrate(&conn)?;
        Ok(Ledger { conn })
    }

    /// Recompute the whole chain. Ok(rows) or a refusal naming the first bad row.
    pub fn verify(&self) -> Result<i64> {
        verify_conn(&self.conn)
    }

    /// Append records in one transaction, after verifying the chain. Returns the new seqs.
    pub fn append_many(&mut self, recs: &[(&str, String, Value)]) -> Result<Vec<i64>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut n = verify_conn(&tx)?;
        let mut prev: String = tx
            .query_row("SELECT hash FROM entries ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
            .optional()?
            .unwrap_or_else(|| ZERO_HASH.to_string());
        let insert = |seq: i64, kind: &str, key: &str, text: &str, prev: &str| -> Result<String> {
            let hash = chain_hash_v2(seq, kind, key, prev, text);
            tx.execute(
                "INSERT INTO entries (seq, kind, key, body, prev, hash, chain_v) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![seq, kind, key, text, prev, hash, CHAIN_V],
            )?;
            Ok(hash)
        };
        // a v1 tail is sealed before anything else is written after it
        let last_v: Option<i64> = tx.query_row("SELECT chain_v FROM entries ORDER BY seq DESC LIMIT 1", [], |r| r.get(0)).optional()?;
        if last_v == Some(1) {
            let rows = v1_rows(&tx)?;
            let seal = serde_json::json!({"seal": "chain-v1", "rows": rows.len(), "v1_digest": v1_digest(&rows)});
            n += 1;
            prev = insert(n, "chain-seal", "chain-v1", &canonical(&seal), &prev)?;
        }
        let mut seqs = vec![];
        for (i, (kind, key, body)) in recs.iter().enumerate() {
            let seq = n + 1 + i as i64;
            prev = insert(seq, kind, key, &canonical(body), &prev)?;
            seqs.push(seq);
        }
        tx.commit()?;
        Ok(seqs)
    }

    pub fn append(&mut self, kind: &str, key: &str, body: &Value) -> Result<i64> {
        Ok(self.append_many(&[(kind, key.to_string(), body.clone())])?[0])
    }

    /// Entries of a kind (and a key, when given), in chain order.
    pub fn entries(&self, kind: &str, key: Option<&str>) -> Result<Vec<Entry>> {
        let mut st = self.conn.prepare("SELECT seq, kind, key, body FROM entries WHERE kind = ?1 AND (?2 IS NULL OR key = ?2) ORDER BY seq")?;
        let rows = st.query_map(params![kind, key], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)))?;
        let mut out = vec![];
        for row in rows {
            let (seq, kind, key, body) = row?;
            out.push(Entry { seq, kind, key, body: serde_json::from_str(&body)? });
        }
        Ok(out)
    }

    pub fn observations(&self, product: &str, version: &str) -> Result<Vec<Observation>> {
        self.entries("observation", Some(&obs_key(product, version)))?.iter().map(|e| Observation::from_value(&e.body)).collect()
    }

    /// The latest score row of product@version under a ruleset digest.
    pub fn latest_score(&self, product: &str, version: &str, digest: &str) -> Result<Option<Value>> {
        Ok(self.entries("score", Some(&obs_key(product, version)))?.into_iter().rev().map(|e| e.body).find(|b| b["ruleset_digest"] == digest))
    }

    /// `scores.jsonl`: every score row in chain order, each line carrying `prev` = sha-256 of the previous line.
    pub fn export_scores(&self) -> Result<String> {
        let mut out = String::new();
        let mut prev = ZERO_HASH.to_string();
        for e in self.entries("score", None)? {
            let mut m: Map<String, Value> = e.body.as_object().cloned().unwrap_or_default();
            m.insert("prev".into(), Value::String(prev.clone()));
            let line = canonical(&Value::Object(m));
            prev = sha256_hex(line.as_bytes());
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }

    /// The chain head to commit as an anchor: `{"schema": "ledger-head/1", "seq": n, "hash": h}` (seq 0 for an empty ledger).
    pub fn head(&self) -> Result<Value> {
        self.verify()?;
        let (seq, hash): (i64, String) = self
            .conn
            .query_row("SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?
            .unwrap_or((0, ZERO_HASH.to_string()));
        Ok(serde_json::json!({"schema": HEAD_V1, "seq": seq, "hash": hash}))
    }

    /// Verify the chain, then require the committed head: row `seq` must still exist with the same hash. A shorter ledger was
    /// truncated; a different hash at that seq was rewritten (a cut and re-forged tail chains by itself, but not to the anchor).
    pub fn verify_anchor(&self, head: &Value) -> Result<i64> {
        let n = self.verify()?;
        if head["schema"] != HEAD_V1 {
            return refused(format!("anchor: not a {HEAD_V1} record"));
        }
        let (Some(seq), Some(hash)) = (head["seq"].as_i64(), head["hash"].as_str()) else { return refused("anchor: needs `seq` and `hash`") };
        if seq == 0 {
            return Ok(n);
        }
        if n < seq {
            return refused(format!("ledger truncated: the committed anchor is at seq {seq}, the ledger has {n} rows"));
        }
        let got: String = self.conn.query_row("SELECT hash FROM entries WHERE seq = ?1", [seq], |r| r.get(0))?;
        if got != hash {
            return refused(format!("ledger rewritten: row {seq} no longer has the committed anchor's hash"));
        }
        Ok(n)
    }

    /// For tests and the tamper proofs: the raw connection.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

pub fn obs_key(product: &str, version: &str) -> String {
    format!("{product}@{version}")
}

fn v1_rows(conn: &Connection) -> Result<Vec<(i64, String, String, String)>> {
    let mut st = conn.prepare("SELECT seq, kind, key, hash FROM entries WHERE chain_v = 1 ORDER BY seq")?;
    let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

type Row = (i64, String, String, String, String, String, i64);

fn verify_conn(conn: &Connection) -> Result<i64> {
    let mut st = conn.prepare("SELECT seq, kind, key, body, prev, hash, chain_v FROM entries ORDER BY seq")?;
    let rows: Vec<Row> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)))?
        .collect::<std::result::Result<_, _>>()?;
    let mut expect_prev = ZERO_HASH.to_string();
    let mut n = 0i64;
    let mut seen_v2 = false;
    let mut v1: Vec<(i64, String, String, String)> = vec![];
    for (seq, kind, key, body, prev, hash, cv) in rows {
        n += 1;
        if seq != n {
            return refused(format!("ledger chain broken: row {n} is missing (next row has seq {seq})"));
        }
        if prev != expect_prev {
            return refused(format!("ledger chain broken at seq {seq}: prev does not match the hash of seq {}", seq - 1));
        }
        let ok = match cv {
            1 if !seen_v2 => chain_hash_v1(&prev, &body) == hash,
            1 => return refused(format!("ledger chain broken at seq {seq}: a v1 row after a v2 row")),
            2 => chain_hash_v2(seq, &kind, &key, &prev, &body) == hash,
            other => return refused(format!("ledger chain broken at seq {seq}: unknown chain version {other}")),
        };
        if !ok {
            return refused(format!("ledger chain broken at seq {seq}: the row (body, kind, key or seq) was edited after it was written"));
        }
        if cv == 1 {
            v1.push((seq, kind, key, hash.clone()));
        } else if !seen_v2 {
            seen_v2 = true;
            // the first v2 row after a v1 tail must be the seal over that tail's (seq, kind, key, hash)
            if !v1.is_empty() {
                let b: Value = serde_json::from_str(&body)?;
                if kind != "chain-seal" || b["v1_digest"].as_str() != Some(v1_digest(&v1).as_str()) {
                    return refused(format!("ledger chain broken at seq {seq}: the chain-seal does not match the v1 rows before it"));
                }
            }
        }
        expect_prev = hash;
    }
    Ok(n)
}

/// Verify a `scores.jsonl` text: every line is a `score/1` row whose `prev` is the sha-256 of the line before. Returns the line count.
pub fn verify_jsonl(text: &str) -> Result<usize> {
    let mut prev = ZERO_HASH.to_string();
    let mut n = 0;
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() {
            return refused(format!("scores.jsonl line {}: empty line", i + 1));
        }
        let v: Value = serde_json::from_str(line).map_err(|e| crate::Error::Refused(format!("scores.jsonl line {}: {e}", i + 1)))?;
        if v["schema"] != SCORE_V1 {
            return refused(format!("scores.jsonl line {}: not a {SCORE_V1} row", i + 1));
        }
        if v["prev"].as_str() != Some(prev.as_str()) {
            return refused(format!("scores.jsonl line {}: prev does not match the line before (an earlier line was edited, removed or reordered)", i + 1));
        }
        prev = sha256_hex(line.as_bytes());
        n += 1;
    }
    Ok(n)
}

/// The committed copy (the trusted branch's) must be a prefix of the current file, line for line, and both must verify.
pub fn anchor(committed: &str, current: &str) -> Result<(usize, usize)> {
    let a = verify_jsonl(committed).map_err(|e| crate::Error::Refused(format!("committed copy: {e}")))?;
    let b = verify_jsonl(current).map_err(|e| crate::Error::Refused(format!("current copy: {e}")))?;
    let (cl, ul): (Vec<&str>, Vec<&str>) = (committed.lines().collect(), current.lines().collect());
    if ul.len() < cl.len() {
        return refused(format!("current scores.jsonl has {} lines, the committed copy {}: history was cut", ul.len(), cl.len()));
    }
    if let Some(i) = cl.iter().zip(&ul).position(|(x, y)| x != y) {
        return refused(format!("scores.jsonl line {} differs from the committed copy: history is append-only", i + 1));
    }
    Ok((a, b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn score_row(v: &str, s: f64) -> Value {
        json!({"schema": "score/1", "product": "example-web", "version": v, "ruleset_digest": "d", "at": "t", "product_score": s, "families": {}, "rules": {}})
    }

    #[test]
    fn the_chain_verifies_and_update_delete_are_refused() {
        let mut l = Ledger::in_memory().unwrap();
        for i in 0..3 {
            l.append("score", &obs_key("example-web", &format!("v{i}")), &score_row(&format!("v{i}"), 0.5)).unwrap();
        }
        assert_eq!(l.verify().unwrap(), 3);
        assert!(l.conn().execute("UPDATE entries SET body = '{}' WHERE seq = 1", []).unwrap_err().to_string().contains("append-only"));
        assert!(l.conn().execute("DELETE FROM entries WHERE seq = 3", []).unwrap_err().to_string().contains("append-only"));
    }

    #[test]
    fn an_earlier_row_edited_behind_the_triggers_is_found_and_writes_refuse() {
        let mut l = Ledger::in_memory().unwrap();
        for i in 0..3 {
            l.append("score", "k", &score_row(&format!("v{i}"), 0.5)).unwrap();
        }
        l.conn().execute_batch("DROP TRIGGER entries_no_update; UPDATE entries SET body = replace(body, '0.5', '0.9') WHERE seq = 2;").unwrap();
        let e = l.verify().unwrap_err().to_string();
        assert!(e.contains("seq 2") && e.contains("edited"), "{e}");
        assert!(l.append("score", "k", &score_row("v9", 1.0)).unwrap_err().to_string().contains("chain broken"));
        // a recomputed hash on the edited row only moves the break to the next row
        let body: String = l.conn().query_row("SELECT body FROM entries WHERE seq = 2", [], |r| r.get(0)).unwrap();
        let prev: String = l.conn().query_row("SELECT prev FROM entries WHERE seq = 2", [], |r| r.get(0)).unwrap();
        l.conn().execute("UPDATE entries SET hash = ?1 WHERE seq = 2", [chain_hash_v2(2, "score", "k", &prev, &body)]).unwrap();
        assert!(l.verify().unwrap_err().to_string().contains("seq 3"));
    }

    #[test]
    fn truncation_and_a_forged_tail_are_found_against_the_committed_head() {
        let mut l = Ledger::in_memory().unwrap();
        for i in 0..3 {
            l.append("score", "k", &score_row(&format!("v{i}"), 0.5)).unwrap();
        }
        let head = l.head().unwrap();
        assert_eq!(head["seq"], 3);
        l.verify_anchor(&head).unwrap();
        l.conn().execute_batch("DROP TRIGGER entries_no_delete; DELETE FROM entries WHERE seq = 3;").unwrap();
        assert_eq!(l.verify().unwrap(), 2, "a cut tail still chains by itself");
        assert!(l.verify_anchor(&head).unwrap_err().to_string().contains("truncated"));
        l.append("score", "k", &score_row("forged", 1.0)).unwrap();
        assert_eq!(l.verify().unwrap(), 3);
        assert!(l.verify_anchor(&head).unwrap_err().to_string().contains("rewritten"));
    }

    #[test]
    fn rekeying_or_rekinding_a_row_is_found() {
        for sql in ["UPDATE entries SET key = 'example-web@v9' WHERE seq = 1", "UPDATE entries SET kind = 'decision' WHERE seq = 2"] {
            let mut l = Ledger::in_memory().unwrap();
            for i in 0..3 {
                l.append("score", "example-web@a1", &score_row(&format!("v{i}"), 0.5)).unwrap();
            }
            l.conn().execute_batch(&format!("DROP TRIGGER entries_no_update; {sql};")).unwrap();
            assert!(l.verify().is_err(), "{sql}");
        }
    }

    #[test]
    fn a_v1_ledger_is_sealed_on_its_first_write_and_its_keys_are_then_protected() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("v1.db");
        {
            // the v1 layout: no chain_v column, hash = sha256(prev || body)
            let c = Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE entries (seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL, body TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL);").unwrap();
            let mut prev = ZERO_HASH.to_string();
            for i in 1..=2i64 {
                let body = canonical(&score_row(&format!("v{i}"), 0.5));
                let hash = sha256_hex(format!("{prev}{body}").as_bytes());
                c.execute("INSERT INTO entries VALUES (?1, 'score', 'example-web@a1', ?2, ?3, ?4)", params![i, body, prev, hash]).unwrap();
                prev = hash;
            }
        }
        let mut l = Ledger::open(&path).unwrap();
        assert_eq!(l.verify().unwrap(), 2);
        let seq = l.append("score", "example-web@a1", &score_row("v3", 0.6)).unwrap();
        assert_eq!(seq, 4, "the first write after a v1 tail is the seal (seq 3)");
        assert_eq!(l.entries("chain-seal", None).unwrap().len(), 1);
        assert_eq!(l.verify().unwrap(), 4);
        l.conn().execute_batch("DROP TRIGGER IF EXISTS entries_no_update; UPDATE entries SET key = 'example-web@zz' WHERE seq = 1;").unwrap();
        assert!(l.verify().unwrap_err().to_string().contains("seal"));
    }

    #[test]
    fn a_deleted_row_is_a_gap() {
        let mut l = Ledger::in_memory().unwrap();
        for i in 0..3 {
            l.append("score", "k", &score_row(&format!("v{i}"), 0.5)).unwrap();
        }
        l.conn().execute_batch("DROP TRIGGER entries_no_delete; DELETE FROM entries WHERE seq = 2;").unwrap();
        assert!(l.verify().unwrap_err().to_string().contains("row 2 is missing"));
    }

    #[test]
    fn scores_jsonl_chains_and_the_committed_copy_must_be_a_prefix() {
        let mut l = Ledger::in_memory().unwrap();
        l.append("score", "k", &score_row("v1", 0.5)).unwrap();
        l.append("score", "k", &score_row("v2", 0.6)).unwrap();
        let committed = l.export_scores().unwrap();
        assert_eq!(verify_jsonl(&committed).unwrap(), 2);
        l.append("score", "k", &score_row("v3", 0.7)).unwrap();
        let current = l.export_scores().unwrap();
        assert_eq!(anchor(&committed, &current).unwrap(), (2, 3));
        // red: an edited earlier line breaks the chain of the current copy
        let edited = current.replacen("0.5", "0.9", 1);
        assert!(anchor(&committed, &edited).unwrap_err().to_string().contains("current copy"));
        // red: a re-chained rewrite (valid chain, different history) is not a prefix
        let mut l2 = Ledger::in_memory().unwrap();
        l2.append("score", "k", &score_row("v1", 0.9)).unwrap();
        l2.append("score", "k", &score_row("v2", 0.6)).unwrap();
        l2.append("score", "k", &score_row("v3", 0.7)).unwrap();
        assert!(anchor(&committed, &l2.export_scores().unwrap()).unwrap_err().to_string().contains("differs from the committed copy"));
        // red: a cut history
        assert!(anchor(&current, &committed).unwrap_err().to_string().contains("history was cut"));
    }
}
