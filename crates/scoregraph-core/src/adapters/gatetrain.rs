//! `gatetrain-stamp`: reads the stamps `gatetrain chain` writes for a green run on a clean tree (`stamp-<sha>.json`).
//!
//! A stamp is cited by its digest (sha-256 of the file's bytes; the file is written once and never changed). It counts as proof
//! of a commit when: `v` is 1, it is not `partial` (a run of some steps proves only those), and every step's `rc` is 0. With
//! `score --stamps <dir>`, an observation is measured only if its `stamp` is such a digest for the observation's own version;
//! otherwise it is `unproven` and cannot raise a score.
use crate::util::sha256_hex;
use crate::Result;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Stamp {
    pub digest: String,
    pub sha: String,
    pub steps: BTreeMap<String, i64>,
    pub partial: bool,
    /// Why it does not count, when it does not.
    pub refused: Option<String>,
}

pub fn parse(bytes: &[u8]) -> Stamp {
    let digest = sha256_hex(bytes);
    let v: Value = serde_json::from_slice(bytes).unwrap_or(Value::Null);
    let sha = v["sha"].as_str().unwrap_or("").to_string();
    let partial = v["partial"].as_bool().unwrap_or(false);
    let steps: BTreeMap<String, i64> = v["steps"]
        .as_array()
        .map(|a| a.iter().filter_map(|s| Some((s["name"].as_str()?.to_string(), s["rc"].as_i64()?))).collect())
        .unwrap_or_default();
    let refused = if v.is_null() {
        Some("not JSON".to_string())
    } else if v["v"] != 1 {
        Some("unknown stamp version".into())
    } else if sha.is_empty() {
        Some("no sha".into())
    } else if partial {
        Some("partial run (--only/--skip): proves only some steps".into())
    } else if steps.is_empty() {
        Some("no steps".into())
    } else if let Some((n, rc)) = steps.iter().find(|(_, rc)| **rc != 0) {
        Some(format!("step {n} rc={rc}"))
    } else {
        None
    };
    Stamp { digest, sha, steps, partial, refused }
}

/// Every `stamp*.json` in `dir`.
pub fn load_dir(dir: &Path) -> Result<Vec<Stamp>> {
    let mut paths: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json") && p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("stamp")))
        .collect();
    paths.sort();
    paths.iter().map(|p| Ok(parse(&std::fs::read(p)?))).collect()
}

/// digest -> commit, for the stamps that count.
pub fn verified(stamps: &[Stamp]) -> BTreeMap<String, String> {
    stamps.iter().filter(|s| s.refused.is_none()).map(|s| (s.digest.clone(), s.sha.clone())).collect()
}

/// One observation per stamp for a chain rule (facts: `green`, `partial`, `steps.<name>` = rc), so "the chain is green on this
/// commit" can itself be a scored rule.
pub fn observation(s: &Stamp, product: &str, rule: &str, rule_version: u32) -> Value {
    json!({"schema": "observation/1", "product": product, "version": s.sha, "rule": {"id": rule, "version": rule_version},
           "context": {"source": "gatetrain-stamp"}, "facts": {"green": s.refused.is_none(), "partial": s.partial, "steps": s.steps},
           "evidence": [format!("stamp:{}", s.digest)], "probe": {"id": "gatetrain-stamp", "version": "1"}, "stamp": s.digest})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn green_full_stamps_count_and_red_or_partial_ones_do_not() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/gatetrain-stamp/fixtures");
        let s = load_dir(&dir).unwrap();
        assert_eq!(s.len(), 3);
        let v = verified(&s);
        assert_eq!(v.len(), 1);
        assert_eq!(v.values().next().unwrap(), "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678");
        let why: Vec<String> = s.iter().filter_map(|x| x.refused.clone()).collect();
        assert!(why.iter().any(|w| w.contains("partial")) && why.iter().any(|w| w.contains("rc=1")), "{why:?}");
        // one changed byte is another digest
        let bytes = std::fs::read(dir.join("stamp-a1b2c3d4e5f60718293a4b5c6d7e8f9012345678.json")).unwrap();
        let mut edited = bytes.clone();
        edited.push(b' ');
        assert_ne!(parse(&bytes).digest, parse(&edited).digest);
    }
}
