//! Small helpers: hashing, canonical JSON, UTC time, JSON lines.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// sha-256 hex of bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// The first `n` hex digits of sha-256, written as letters (0-f -> a-p). Ids and placeholders built from it never contain a run
/// of digits, so the PII scan can never mistake one for a phone number.
pub fn letter_hash(bytes: &[u8], n: usize) -> String {
    sha256_hex(bytes).chars().take(n).map(|c| (b'a' + c.to_digit(16).unwrap_or(0) as u8) as char).collect()
}

/// Canonical JSON: serde_json's map is a BTreeMap here (no `preserve_order`), so keys come out sorted and there is no whitespace.
pub fn canonical(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// Round to six decimals so a score prints the same on every platform.
pub fn round6(x: f64) -> f64 {
    (x * 1_000_000.0).round() / 1_000_000.0
}

/// Now, as `YYYY-MM-DDTHH:MM:SSZ` (UTC; no clock crate needed).
pub fn now_utc() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    iso_from_unix(secs)
}

/// Unix seconds to `YYYY-MM-DDTHH:MM:SSZ` (Howard Hinnant's civil-from-days).
pub fn iso_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// Every non-blank line of a JSON-lines file, parsed; an error names the line.
pub fn read_jsonl(path: &Path) -> crate::Result<Vec<Value>> {
    let text = std::fs::read_to_string(path)?;
    parse_jsonl(&text, &path.display().to_string())
}

pub fn parse_jsonl(text: &str, name: &str) -> crate::Result<Vec<Value>> {
    let mut out = vec![];
    for (i, line) in text.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(l).map_err(|e| crate::Error::Invalid(format!("{name}:{}: {e}", i + 1)))?;
        out.push(v);
    }
    Ok(out)
}

/// A JSON file, or a JSON-lines file when the name ends in `.jsonl` (an array file yields its elements).
pub fn read_records(path: &Path) -> crate::Result<Vec<Value>> {
    if path.extension().is_some_and(|e| e == "jsonl") {
        return read_jsonl(path);
    }
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path)?)
        .map_err(|e| crate::Error::Invalid(format!("{}: {e}", path.display())))?;
    Ok(match v {
        Value::Array(a) => a,
        other => vec![other],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_time_and_hash_are_stable() {
        assert_eq!(iso_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_from_unix(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(canonical(&serde_json::json!({"b": 1, "a": [2, {"d": 1, "c": 0}]})), r#"{"a":[2,{"c":0,"d":1}],"b":1}"#);
    }
}
