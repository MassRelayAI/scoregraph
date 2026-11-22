//! PII redaction at the edge, and the scan that refuses a record on ingest.
//!
//! Adapters call [`Redactor::text`] on every free-text field and [`Redactor::name`] on every name field before a record leaves
//! them: emails, phone numbers and known names become hashed placeholders (`[email:1a2b3c4d]`), so the same person maps to the
//! same placeholder within one salt and the value itself is never stored. Names in free text can only be found when the adapter
//! knows them (an author field) or a names list is given; anything else is the product edge's job.
//!
//! [`scan`] runs again on ingest and REFUSES a record that still holds an email or a phone number.
use crate::util::letter_hash;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub const SCANNER: &str = "scoregraph-redact/1";
pub const SALT_ENV: &str = "SCOREGRAPH_REDACT_SALT";

fn email_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}").unwrap())
}

/// A run of digits with optional `+`, spaces, dots, dashes and parentheses; counted as a phone when it holds 8 to 15 digits and is
/// not an ISO date or time.
fn phone_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\+?\(?\d[\d\s().-]{6,}\d").unwrap())
}

fn date_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?$").unwrap())
}

fn is_phone(m: &str) -> bool {
    let digits = m.chars().filter(char::is_ascii_digit).count();
    (8..=15).contains(&digits) && !date_re().is_match(m.trim())
}

pub struct Redactor {
    salt: String,
    salted: bool,
    names: Vec<String>,
    pub removed: BTreeMap<String, u64>,
}

impl Redactor {
    /// The salt comes from `SCOREGRAPH_REDACT_SALT` when set (recommended: placeholders then cannot be reversed by guessing).
    pub fn from_env() -> Redactor {
        match std::env::var(SALT_ENV) {
            Ok(s) if !s.is_empty() => Redactor::new(&s, true),
            _ => Redactor::new("scoregraph-unsalted", false),
        }
    }

    pub fn new(salt: &str, salted: bool) -> Redactor {
        Redactor { salt: salt.into(), salted, names: vec![], removed: BTreeMap::new() }
    }

    /// Names to remove from free text wherever they appear (whole words, any case).
    pub fn with_names(mut self, names: &[String]) -> Redactor {
        self.names.extend(names.iter().filter(|n| n.trim().chars().count() >= 2).map(|n| n.trim().to_string()));
        self
    }

    fn placeholder(&self, class: &str, value: &str) -> String {
        // letters only: a placeholder must never look like a phone number to the ingest scan
        let tag = letter_hash(format!("{}|{class}|{}", self.salt, value.trim().to_lowercase()).as_bytes(), 8);
        format!("[{class}:{tag}]")
    }

    fn bump(&mut self, class: &str) {
        *self.removed.entry(class.into()).or_default() += 1;
    }

    /// A name field: always a placeholder (empty stays empty). The name is also removed from later free text.
    pub fn name(&mut self, name: &str) -> String {
        if name.trim().is_empty() {
            return String::new();
        }
        if !self.names.iter().any(|n| n.eq_ignore_ascii_case(name.trim())) && name.trim().chars().count() >= 2 {
            self.names.push(name.trim().to_string());
        }
        self.bump("name");
        self.placeholder("name", name)
    }

    /// Free text: emails, phone numbers and known names become placeholders.
    pub fn text(&mut self, text: &str) -> String {
        let mut out = String::new();
        let mut last = 0;
        let mut n = 0;
        for m in email_re().find_iter(text) {
            out.push_str(&text[last..m.start()]);
            out.push_str(&self.placeholder("email", m.as_str()));
            last = m.end();
            n += 1;
        }
        out.push_str(&text[last..]);
        for _ in 0..n {
            self.bump("email");
        }
        let src = out;
        let mut out = String::new();
        let mut last = 0;
        let mut n = 0;
        for m in phone_re().find_iter(&src) {
            if !is_phone(m.as_str()) {
                continue;
            }
            out.push_str(&src[last..m.start()]);
            out.push_str(&self.placeholder("phone", m.as_str()));
            last = m.end();
            n += 1;
        }
        out.push_str(&src[last..]);
        for _ in 0..n {
            self.bump("phone");
        }
        for name in self.names.clone() {
            let re = Regex::new(&format!(r"(?i)\b{}\b", regex::escape(&name))).unwrap();
            let hits = re.find_iter(&out).count();
            if hits > 0 {
                let ph = self.placeholder("name", &name);
                out = re.replace_all(&out, regex::NoExpand(&ph)).into_owned();
                for _ in 0..hits {
                    self.bump("name");
                }
            }
        }
        out
    }

    /// The `redaction` block a record carries.
    pub fn report(&self) -> Value {
        json!({"scanner": SCANNER, "salted": self.salted, "removed": self.removed})
    }
}

/// What the ingest scan finds in a text: the classes found (never the values).
pub fn scan(text: &str) -> Vec<&'static str> {
    let mut out = vec![];
    if email_re().is_match(text) {
        out.push("email");
    }
    if phone_re().find_iter(text).any(|m| is_phone(m.as_str())) {
        out.push("phone");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_phones_and_names_become_stable_placeholders() {
        let mut r = Redactor::new("s", true);
        let author = r.name("Jane Roe");
        assert!(author.starts_with("[name:"));
        let t = r.text("Jane Roe here, mail jane.roe@example.com or call +1 (555) 010-2345. jane roe again. Build 2026-11-22.");
        assert!(!t.contains("example.com") && !t.contains("555") && !t.to_lowercase().contains("jane"), "{t}");
        assert!(t.contains("2026-11-22"), "a date is not a phone: {t}");
        assert_eq!(t.matches(&author).count(), 2, "{t}");
        assert_eq!(r.removed["email"], 1);
        assert_eq!(r.removed["phone"], 1);
        assert_eq!(r.removed["name"], 3);
        // the same value gives the same placeholder; another salt another one
        let mut r2 = Redactor::new("s", true);
        assert_eq!(r2.name("jane roe"), author);
        assert_ne!(Redactor::new("t", true).name("Jane Roe"), author);
    }

    #[test]
    fn the_ingest_scan_finds_what_redaction_missed() {
        assert_eq!(scan("write to a.b@example.org"), vec!["email"]);
        assert_eq!(scan("call 0812 3456 7890"), vec!["phone"]);
        assert!(scan("version 1.2.3 on 2026-11-22, 5 stars, order 1234").is_empty());
        let mut r = Redactor::new("s", true);
        assert!(scan(&r.text("a.b@example.org 0812 3456 7890")).is_empty());
    }
}
