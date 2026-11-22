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

/// The class of a digit run: `phone` for 8 to 15 digits, `number` for more (card, account, id numbers), none below 8 or for an ISO
/// date or time.
fn digit_class(m: &str) -> Option<&'static str> {
    let digits = m.chars().filter(char::is_ascii_digit).count();
    if digits < 8 || date_re().is_match(m.trim()) {
        None
    } else if digits <= 15 {
        Some("phone")
    } else {
        Some("number")
    }
}

/// Normalise before matching: fullwidth forms (U+FF01..U+FF5E: digits, `@`, `+`, letters) become ASCII, and percent-encoded
/// printable ASCII (`%40` -> `@`) is decoded, so neither can carry an email or a number past the patterns.
pub fn normalize(text: &str) -> String {
    let ascii: String = text
        .chars()
        .map(|c| match c as u32 {
            0xFF01..=0xFF5E => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            0x3000 => ' ',
            _ => c,
        })
        .collect();
    let b = ascii.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(x) = hex.filter(|x| (0x20..0x7F).contains(x)) {
                out.push(x);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or(ascii)
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

    /// Free text (normalised first): emails, phone numbers, long digit runs and known names become placeholders.
    pub fn text(&mut self, text: &str) -> String {
        let text = &normalize(text);
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
        let mut found = vec![];
        for m in phone_re().find_iter(&src) {
            let Some(class) = digit_class(m.as_str()) else { continue };
            out.push_str(&src[last..m.start()]);
            out.push_str(&self.placeholder(class, m.as_str()));
            last = m.end();
            found.push(class);
        }
        out.push_str(&src[last..]);
        for class in found {
            self.bump(class);
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

/// What the ingest scan finds in a text (normalised first): the classes found, never the values.
pub fn scan(text: &str) -> Vec<&'static str> {
    let text = &normalize(text);
    let mut out = vec![];
    if email_re().is_match(text) {
        out.push("email");
    }
    for m in phone_re().find_iter(text) {
        if let Some(c) = digit_class(m.as_str()) {
            if !out.contains(&c) {
                out.push(c);
            }
        }
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
    fn long_digit_runs_percent_encoded_emails_and_fullwidth_digits_are_redacted() {
        let mut r = Redactor::new("s", true);
        for raw in [
            "card 4111 1111 1111 1111 2222 thanks",
            "account 12345678901234567890",
            "mail me a.b%40example.com please",
            "call \u{ff10}\u{ff18}\u{ff11}\u{ff12} \u{ff13}\u{ff14}\u{ff15}\u{ff16} \u{ff17}\u{ff18}\u{ff19}\u{ff10}",
        ] {
            assert!(!scan(raw).is_empty(), "the ingest scan must refuse: {raw}");
            let t = r.text(raw);
            assert!(scan(&t).is_empty(), "{raw} -> {t}");
            assert!(!t.contains("1111") && !t.contains("12345678") && !t.contains("%40") && !t.contains('\u{ff18}'), "{t}");
        }
        assert!(scan("on 2026-11-22 at 10:00, order 1234").is_empty());
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
