//! Google Play Developer Reviews API.
//!
//! Request (the fetcher's): `GET https://androidpublisher.googleapis.com/androidpublisher/v3/applications/<package>/reviews`
//! with an OAuth 2.0 token of a service account that has access to the app in the Play Console (scope
//! `https://www.googleapis.com/auth/androidpublisher`). Pages follow `tokenPagination.nextPageToken` (`?token=`).
//!
//! **The API returns only reviews WITH a written comment, and only those created or modified in the LAST WEEK** (quota: 200
//! GET requests per hour per app). History is therefore kept here, not there: poll at least every few days, and every page is
//! added to the ledger, which keeps every review forever. A review's feedback id comes from its `reviewId` and
//! `lastModified`, so re-polling the same review is a no-op and an edited review is a new record.
//!
//! Response: `reviews[]` of `{"reviewId", "authorName", "comments": [{"userComment": {"text", "lastModified": {"seconds",
//! "nanos"}, "starRating", "reviewerLanguage", "appVersionName", ...}}, {"developerComment": {...}}]}`. `authorName` is never
//! stored: it is only used to redact the text. `text` holds the title and body separated by a tab.
use super::posthog::add_counts;
use super::{env_or_placeholder, env_status, feedback_id, feedback_record, Output, Plan};
use crate::redact::Redactor;
use crate::util::iso_from_unix;
use crate::{invalid, Result};
use serde_json::{json, Value};

pub const ENV: [&str; 2] = ["PLAY_PACKAGE_NAME", "GOOGLE_APPLICATION_CREDENTIALS"];

pub fn plan() -> Plan {
    let (configured, env) = env_status(&ENV);
    Plan {
        adapter: "play-reviews".into(),
        configured,
        env,
        method: "GET".into(),
        url: format!("https://androidpublisher.googleapis.com/androidpublisher/v3/applications/{}/reviews?maxResults=100", env_or_placeholder("PLAY_PACKAGE_NAME")),
        headers: vec!["Authorization: Bearer <OAuth 2.0 token of the service account in ${GOOGLE_APPLICATION_CREDENTIALS}, scope androidpublisher>".into()],
        body: None,
        notes: vec![
            "only reviews with comments, only the last 7 days: schedule the fetch at least every 3 days or history is lost".into(),
            "follow tokenPagination.nextPageToken with ?token=<it>; 200 GET requests per hour per app".into(),
            "older reviews exist only in the Play Console's monthly CSV reports".into(),
        ],
    }
}

pub fn parse(page: &Value, product: &str) -> Result<Output> {
    let Some(reviews) = page["reviews"].as_array() else {
        // an empty week returns `{}`: not an error
        if page.as_object().is_some_and(|o| o.is_empty() || !o.contains_key("reviews")) {
            return Ok(Output { redaction: json!({}), ..Default::default() });
        }
        return invalid("play-reviews: `reviews` is not an array");
    };
    let mut out = Output::default();
    let mut totals = json!({});
    for r in reviews {
        let id = r["reviewId"].as_str().unwrap_or("");
        let Some(uc) = r["comments"].as_array().and_then(|c| c.iter().find_map(|x| x.get("userComment"))) else {
            out.skipped.push("no userComment".into());
            continue;
        };
        let secs = uc["lastModified"]["seconds"].as_str().and_then(|s| s.parse::<i64>().ok()).or_else(|| uc["lastModified"]["seconds"].as_i64()).unwrap_or(0);
        let mut red = Redactor::from_env();
        if let Some(n) = r["authorName"].as_str().filter(|n| !n.is_empty()) {
            red.name(n);
        }
        let text = red.text(&uc["text"].as_str().unwrap_or("").replace('\t', "\n"));
        if text.trim().is_empty() {
            out.skipped.push("empty review".into());
            continue;
        }
        add_counts(&mut totals, &red);
        let mut ctx = json!({"platform": "android"});
        for (k, f) in [("language", "reviewerLanguage"), ("app_version", "appVersionName")] {
            if let Some(v) = uc[f].as_str() {
                ctx[k] = json!(v);
            }
        }
        out.feedback.push(feedback_record(
            feedback_id("play", &format!("{id}@{secs}")),
            product,
            "store",
            &iso_from_unix(secs),
            text,
            vec![format!("play:review:{}", crate::util::letter_hash(id.as_bytes(), 12))],
            ctx,
            uc["starRating"].as_f64(),
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
    use crate::ledger::Ledger;
    use std::path::Path;

    fn page(n: &str) -> Value {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/play-reviews/fixtures").join(n);
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    #[test]
    fn two_overlapping_weekly_polls_keep_the_union_and_an_edit_is_a_new_record() {
        let a = parse(&page("reviews-week-1.json"), "example-app").unwrap();
        let b = parse(&page("reviews-week-2.json"), "example-app").unwrap();
        assert_eq!((a.feedback.len(), b.feedback.len()), (2, 2));
        let all = serde_json::to_string(&[&a.feedback, &b.feedback]).unwrap();
        assert!(!all.contains("Alex Kim") && !all.to_lowercase().contains("alex"), "{all}");
        let mut l = Ledger::in_memory().unwrap();
        let r1 = crate::feedback::add(&mut l, &a.feedback, false).unwrap();
        let r2 = crate::feedback::add(&mut l, &b.feedback, false).unwrap();
        // week 2 repeats one review unchanged (skipped) and holds one edit of the other (a new record)
        assert_eq!((r1.added.len(), r2.added.len(), r2.already_stored.len()), (2, 1, 1));
        assert_eq!(l.entries("feedback", None).unwrap().len(), 3);
        assert!(parse(&json!({}), "example-app").unwrap().feedback.is_empty());
    }
}
