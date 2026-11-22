//! Apple App Store Connect customer reviews.
//!
//! Request (the fetcher's): `GET https://api.appstoreconnect.apple.com/v1/apps/<app id>/customerReviews?sort=-createdDate&limit=200`,
//! `Authorization: Bearer <JWT>` where the JWT is ES256-signed with an App Store Connect API key (`kid` = key id, `iss` = issuer id,
//! `aud` = `appstoreconnect-v1`, `exp` at most 20 minutes ahead). Pages follow `links.next` until it is absent.
//!
//! Response (JSON:API): `data[]` of `{"type": "customerReviews", "id", "attributes": {"rating", "title", "body",
//! "reviewerNickname", "createdDate", "territory"}}`. The nickname is never stored: it is only used to redact the text.
//! The response shape here follows Apple's public reference as commonly documented; confirm it on the first real export
//! (docs/adapters.md lists this as open).
use super::posthog::add_counts;
use super::{env_or_placeholder, env_status, feedback_id, feedback_record, Output, Plan};
use crate::redact::Redactor;
use crate::{invalid, Result};
use serde_json::{json, Value};

pub const ENV: [&str; 4] = ["ASC_APP_ID", "ASC_ISSUER_ID", "ASC_KEY_ID", "ASC_PRIVATE_KEY_PATH"];

pub fn plan() -> Plan {
    let (configured, env) = env_status(&ENV);
    Plan {
        adapter: "appstore-reviews".into(),
        configured,
        env,
        method: "GET".into(),
        url: format!("https://api.appstoreconnect.apple.com/v1/apps/{}/customerReviews?sort=-createdDate&limit=200", env_or_placeholder("ASC_APP_ID")),
        headers: vec!["Authorization: Bearer <JWT signed ES256 with the key at ${ASC_PRIVATE_KEY_PATH}, kid ${ASC_KEY_ID}, iss ${ASC_ISSUER_ID}, aud appstoreconnect-v1>".into()],
        body: None,
        notes: vec![
            "follow links.next until it is absent; save each page and pass it with --in".into(),
            "the .p8 private key stays where ASC_PRIVATE_KEY_PATH points; it is never copied into this repository".into(),
        ],
    }
}

pub fn parse(page: &Value, product: &str) -> Result<Output> {
    let Some(data) = page["data"].as_array() else { return invalid("appstore-reviews: page has no `data` array") };
    let mut out = Output::default();
    let mut totals = json!({});
    for d in data {
        if d["type"] != "customerReviews" {
            out.skipped.push(format!("type {} is not customerReviews", d["type"]));
            continue;
        }
        let a = &d["attributes"];
        let id = d["id"].as_str().unwrap_or("");
        let mut red = Redactor::from_env();
        let nick = a["reviewerNickname"].as_str().unwrap_or("");
        if !nick.is_empty() {
            red.name(nick);
        }
        let title = a["title"].as_str().unwrap_or("");
        let body = a["body"].as_str().unwrap_or("");
        let text = red.text(&[title, body].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join("\n"));
        if text.trim().is_empty() {
            out.skipped.push("empty review".into());
            continue;
        }
        add_counts(&mut totals, &red);
        let ctx = match a["territory"].as_str() {
            Some(t) => json!({"territory": t, "platform": "ios"}),
            None => json!({"platform": "ios"}),
        };
        out.feedback.push(feedback_record(
            feedback_id("appstore", id),
            product,
            "store",
            a["createdDate"].as_str().unwrap_or(""),
            text,
            vec![format!("appstore:review:{}", crate::util::letter_hash(id.as_bytes(), 12))],
            ctx,
            a["rating"].as_f64(),
            "customer",
            &red,
        ));
    }
    out.redaction = totals;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn reviews_become_feedback_and_the_nickname_is_never_stored() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/appstore-reviews/fixtures/customer-reviews-page.json");
        let page: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let o = parse(&page, "example-app").unwrap();
        assert_eq!(o.feedback.len(), 2);
        let all = serde_json::to_string(&o.feedback).unwrap();
        assert!(!all.contains("HappyPanda77") && !all.contains("@example.net"), "{all}");
        assert_eq!(o.feedback[0]["rating"], 2.0);
        assert_eq!(o.feedback[0]["context"]["territory"], "USA");
        for f in &o.feedback {
            crate::model::Feedback::from_value(f).unwrap();
        }
        assert!(plan().url.contains("customerReviews"));
    }
}
