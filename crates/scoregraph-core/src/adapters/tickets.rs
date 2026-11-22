//! Support tickets from an email inbox or a helpdesk, in one generic JSON shape (map your helpdesk's export onto it):
//!
//! ```json
//! {"tickets": [{"id": "T-1", "subject": "...", "body": "...", "created_at": "2026-01-01T00:00:00Z",
//!               "requester": {"name": "...", "email": "..."}, "tags": ["billing"], "url": "https://helpdesk.example.com/t/1",
//!               "surface": "settings/billing"}]}
//! ```
//! `requester` is never stored: its name and email only redact the text. `id` becomes an opaque feedback id; `url` is kept as a
//! link only when it holds no email or phone number. A ticket tagged `spam` is skipped.
use super::posthog::add_counts;
use super::{feedback_id, feedback_record, Output};
use crate::redact::{scan, Redactor};
use crate::{invalid, Result};
use serde_json::{json, Value};

pub fn parse(doc: &Value, product: &str) -> Result<Output> {
    let Some(ts) = doc["tickets"].as_array() else { return invalid("tickets: needs a `tickets` array") };
    let mut out = Output::default();
    let mut totals = json!({});
    for t in ts {
        let Some(id) = t["id"].as_str().filter(|s| !s.is_empty()) else { return invalid("tickets: every ticket needs an `id`") };
        let tags: Vec<String> = t["tags"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
        if tags.iter().any(|x| x == "spam") {
            out.skipped.push("tagged spam".into());
            continue;
        }
        let mut red = Redactor::from_env();
        if let Some(n) = t["requester"]["name"].as_str() {
            red.name(n);
        }
        let joined = [t["subject"].as_str().unwrap_or(""), t["body"].as_str().unwrap_or("")].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join("\n");
        let text = red.text(&joined);
        if text.trim().is_empty() {
            out.skipped.push("empty ticket".into());
            continue;
        }
        add_counts(&mut totals, &red);
        let mut links = vec![];
        if let Some(u) = t["url"].as_str().filter(|u| scan(u).is_empty()) {
            links.push(u.to_string());
        }
        let mut ctx = json!({});
        if !tags.is_empty() {
            ctx["tags"] = json!(tags.join(","));
        }
        let mut rec = feedback_record(feedback_id("ticket", id), product, "ticket", t["created_at"].as_str().unwrap_or(""), text, links, ctx, None, "customer", &red);
        if let Some(s) = t["surface"].as_str() {
            rec["surface"] = json!(s);
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
    fn tickets_become_feedback_without_the_requester() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/tickets/fixtures/helpdesk-export.json");
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let o = parse(&doc, "example-web").unwrap();
        assert_eq!((o.feedback.len(), o.skipped.len()), (2, 1));
        let all = serde_json::to_string(&o.feedback).unwrap();
        assert!(!all.contains("Robin Park") && !all.contains("robin.park@example.com") && !all.contains("7946 0199"), "{all}");
        assert_eq!(o.feedback[0]["surface"], "settings/billing");
        for f in &o.feedback {
            crate::model::Feedback::from_value(f).unwrap();
            assert!(scan(&serde_json::to_string(f).unwrap()).is_empty());
        }
        assert!(parse(&json!({"tickets": [{"subject": "x"}]}), "p").is_err());
    }
}
