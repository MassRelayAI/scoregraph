//! Input adapters. Each one turns an export into `feedback/1` or `observation/1` records, redacting PII at the edge.
//!
//! The engine opens no socket: an adapter for an API (`posthog`, `appstore-reviews`, `play-reviews`) has a **plan** (the exact
//! request a fetcher must make, with the NAMES of the environment variables that hold its keys, never their values) and a
//! **parser** for the response body. A fetcher (curl in a CI step, a scheduled job) runs the request and hands the body to
//! `scoregraph adapter <name> --in <file>`. Until those variables are set the adapter is inert: `--plan` says what is missing.
//!
//! | adapter | input | output |
//! |---|---|---|
//! | `comparegraph-export` | `export csv` folder | claims for `score --claims` |
//! | `gatetrain-stamp` | `stamp-<sha>.json` folder | verified stamps for `score --stamps`, chain observations |
//! | `posthog-surveys` | Query API response, survey events | feedback (source analytics) |
//! | `posthog-funnel` | Query API response, funnel steps | observation (flow facts) |
//! | `appstore-reviews` | App Store Connect customer reviews page | feedback (source store) |
//! | `play-reviews` | Google Play Developer Reviews page | feedback (source store) |
//! | `tickets` | generic helpdesk JSON | feedback (source ticket) |
//! | `intake` | `intake/1` records from a feedback door | feedback |
pub mod appstore;
pub mod comparegraph;
pub mod gatetrain;
pub mod intake;
pub mod play;
pub mod posthog;
pub mod tickets;

use crate::redact::Redactor;
use serde::Serialize;
use serde_json::{json, Value};

pub const NAMES: [&str; 8] = ["comparegraph-export", "gatetrain-stamp", "posthog-surveys", "posthog-funnel", "appstore-reviews", "play-reviews", "tickets", "intake"];

/// What an adapter produced from one input.
#[derive(Debug, Default, Serialize)]
pub struct Output {
    pub feedback: Vec<Value>,
    pub observations: Vec<Value>,
    /// Records skipped, with why (a duplicate, an empty text).
    pub skipped: Vec<String>,
    pub redaction: Value,
}

/// The request a fetcher must make. Values of keys are never here, only the names of the variables that hold them.
#[derive(Debug, Serialize, PartialEq)]
pub struct Plan {
    pub adapter: String,
    pub configured: bool,
    /// Variable name -> set | unset (status only).
    pub env: Vec<(String, String)>,
    pub method: String,
    pub url: String,
    pub headers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    pub notes: Vec<String>,
}

pub(crate) fn env_status(names: &[&str]) -> (bool, Vec<(String, String)>) {
    let st: Vec<(String, String)> = names
        .iter()
        .map(|n| (n.to_string(), if std::env::var(n).is_ok_and(|v| !v.is_empty()) { "set" } else { "unset" }.to_string()))
        .collect();
    (st.iter().all(|(_, s)| s == "set"), st)
}

/// The value of a non-secret variable for a URL, or `${NAME}` when unset.
pub(crate) fn env_or_placeholder(name: &str) -> String {
    std::env::var(name).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| format!("${{{name}}}"))
}

/// An opaque, stable feedback id from an external id.
pub(crate) fn feedback_id(prefix: &str, external: &str) -> String {
    format!("fb-{prefix}-{}", crate::util::letter_hash(external.as_bytes(), 12))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn feedback_record(
    id: String,
    product: &str,
    source: &str,
    received_at: &str,
    text: String,
    links: Vec<String>,
    context: Value,
    rating: Option<f64>,
    reporter_class: &str,
    r: &Redactor,
) -> Value {
    let mut v = json!({"schema": "feedback/1", "id": id, "product": product, "source": source, "received_at": received_at,
        "text": text, "status": "new", "reporter_class": reporter_class, "redaction": r.report()});
    if !links.is_empty() {
        v["links"] = json!(links);
    }
    if context.as_object().is_some_and(|m| !m.is_empty()) {
        v["context"] = context;
    }
    if let Some(x) = rating {
        v["rating"] = json!(x);
    }
    v
}
