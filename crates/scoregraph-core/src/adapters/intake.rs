//! `intake/1`: the generic body a product's own feedback door (a widget, a form, an HTTP endpoint the product runs) exports.
//! scoregraph runs no server; the product stores these and hands them over as a JSON-lines file.
//!
//! ```json
//! {"schema": "intake/1", "product": "example-web", "product_version": "a1b2c3d", "submitted_at": "2026-01-01T00:00:00Z",
//!  "surface": "checkout", "text": "...", "rating": 3, "source": "customer", "reporter_class": "customer",
//!  "context": {"viewport": "390", "role": "member", "locale": "en"}, "links": [], "client_ref": "opaque-123"}
//! ```
//! Required: `schema`, `product`, `submitted_at`, `text`. `source` is `customer` (default), `tester` or `founder`. `client_ref` is
//! the product's own opaque id (never an account id or an email); without it the id is derived from the record. No other field is
//! accepted: a door that sends an email, a name or a device id is refused, not filtered.
use super::posthog::add_counts;
use super::{feedback_id, feedback_record, Output};
use crate::redact::Redactor;
use crate::util::canonical;
use crate::{invalid, Result};
use serde_json::{json, Value};

pub const INTAKE_V1: &str = "intake/1";
pub const FIELDS: [&str; 12] = ["schema", "product", "product_version", "submitted_at", "surface", "text", "rating", "source", "reporter_class", "context", "links", "client_ref"];
pub const REQUIRED: [&str; 4] = ["schema", "product", "submitted_at", "text"];

pub fn parse(records: &[Value]) -> Result<Output> {
    let mut out = Output::default();
    let mut totals = json!({});
    for (i, r) in records.iter().enumerate() {
        let n = i + 1;
        let Some(o) = r.as_object() else { return invalid(format!("intake record {n}: not an object")) };
        if let Some(k) = o.keys().find(|k| !FIELDS.contains(&k.as_str())) {
            return invalid(format!("intake record {n}: field `{k}` is not part of intake/1 (refused, not filtered)"));
        }
        crate::model::require(r, &REQUIRED, &format!("intake record {n}"))?;
        if r["schema"] != INTAKE_V1 {
            return invalid(format!("intake record {n}: schema must be `{INTAKE_V1}`"));
        }
        let source = r["source"].as_str().unwrap_or("customer");
        if !["customer", "tester", "founder"].contains(&source) {
            return invalid(format!("intake record {n}: source `{source}` (customer, tester or founder)"));
        }
        let mut ctx = json!({});
        if let Some(c) = r["context"].as_object() {
            for (k, v) in c {
                let Some(s) = v.as_str() else { return invalid(format!("intake record {n}: context.{k} must be a string")) };
                ctx[k] = json!(s);
            }
        }
        let mut red = Redactor::from_env();
        let text = red.text(r["text"].as_str().unwrap_or(""));
        if text.trim().is_empty() {
            out.skipped.push(format!("record {n}: empty text"));
            continue;
        }
        add_counts(&mut totals, &red);
        let ext = r["client_ref"].as_str().map(str::to_string).unwrap_or_else(|| canonical(r));
        let links: Vec<String> = r["links"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|s| red.text(s))).collect()).unwrap_or_default();
        let mut rec = feedback_record(
            feedback_id("intake", &ext),
            r["product"].as_str().unwrap_or(""),
            source,
            r["submitted_at"].as_str().unwrap_or(""),
            text,
            links,
            ctx,
            r["rating"].as_f64(),
            r["reporter_class"].as_str().unwrap_or(source),
            &red,
        );
        for k in ["product_version", "surface"] {
            if let Some(v) = r[k].as_str() {
                rec[k] = json!(v);
            }
        }
        out.feedback.push(rec);
    }
    out.redaction = totals;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn intake_records_become_feedback_and_extra_fields_are_refused() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/intake/fixtures/intake.jsonl");
        let recs = crate::util::read_jsonl(&p).unwrap();
        let o = parse(&recs).unwrap();
        assert_eq!(o.feedback.len(), 2);
        assert_eq!(o.feedback[0]["surface"], "checkout");
        assert!(!serde_json::to_string(&o.feedback).unwrap().contains("@example.org"));
        for f in &o.feedback {
            crate::model::Feedback::from_value(f).unwrap();
        }
        let bad = json!({"schema": "intake/1", "product": "p", "submitted_at": "t", "text": "x", "email": "a@example.org"});
        assert!(parse(&[bad]).unwrap_err().to_string().contains("`email` is not part of intake/1"));
        assert!(parse(&[json!({"schema": "intake/1", "product": "p", "text": "x"})]).unwrap_err().to_string().contains("submitted_at"));
    }
}
