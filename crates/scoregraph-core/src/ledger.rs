//! The ledger: one append-only, hash-chained SQLite table (`ledger/schema.sql`), and the exported `scores.jsonl`.
//!
//! - **SQLite**: `hash = sha256(prev || body)`. Triggers refuse UPDATE and DELETE; [`Ledger::verify`] recomputes every hash, so a
//!   row edited behind the triggers' back (a dropped trigger, another tool) is found, and every write refuses a broken chain.
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

fn chain_hash(prev: &str, body: &str) -> String {
    sha256_hex(format!("{prev}{body}").as_bytes())
}

impl Ledger {
    pub fn open(path: &Path) -> Result<Ledger> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('format', 'scoregraph-ledger/1')", [])?;
        Ok(Ledger { conn })
    }

    pub fn in_memory() -> Result<Ledger> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Ledger { conn })
    }

    /// Recompute the whole chain. Ok(rows) or a refusal naming the first bad row.
    pub fn verify(&self) -> Result<i64> {
        verify_conn(&self.conn)
    }

    /// Append records in one transaction, after verifying the chain. Returns the new seqs.
    pub fn append_many(&mut self, recs: &[(&str, String, Value)]) -> Result<Vec<i64>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n = verify_conn(&tx)?;
        let mut prev: String = tx
            .query_row("SELECT hash FROM entries ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
            .optional()?
            .unwrap_or_else(|| ZERO_HASH.to_string());
        let mut seqs = vec![];
        for (i, (kind, key, body)) in recs.iter().enumerate() {
            let seq = n + 1 + i as i64;
            let text = canonical(body);
            let hash = chain_hash(&prev, &text);
            tx.execute("INSERT INTO entries (seq, kind, key, body, prev, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![seq, kind, key, text, prev, hash])?;
            prev = hash;
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

    /// For tests and the tamper proofs: the raw connection.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

pub fn obs_key(product: &str, version: &str) -> String {
    format!("{product}@{version}")
}

fn verify_conn(conn: &Connection) -> Result<i64> {
    let mut st = conn.prepare("SELECT seq, body, prev, hash FROM entries ORDER BY seq")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)))?;
    let mut expect_prev = ZERO_HASH.to_string();
    let mut n = 0i64;
    for row in rows {
        let (seq, body, prev, hash) = row?;
        n += 1;
        if seq != n {
            return refused(format!("ledger chain broken: row {n} is missing (next row has seq {seq})"));
        }
        if prev != expect_prev {
            return refused(format!("ledger chain broken at seq {seq}: prev does not match the hash of seq {}", seq - 1));
        }
        if chain_hash(&prev, &body) != hash {
            return refused(format!("ledger chain broken at seq {seq}: the body was edited after it was written"));
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
        l.conn().execute("UPDATE entries SET hash = ?1 WHERE seq = 2", [chain_hash(&prev, &body)]).unwrap();
        assert!(l.verify().unwrap_err().to_string().contains("seq 3"));
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
