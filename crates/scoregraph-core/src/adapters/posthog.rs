//! PostHog-compatible analytics, through its Query API (`POST <host>/api/projects/<project id>/query/`, body
//! `{"query": {"kind": "HogQLQuery", "query": "<HogQL>"}}`, header `Authorization: Bearer <personal API key>` with the
//! **Query Read** permission; project-level limits 240 requests a minute and 2,400 an hour; without a `LIMIT` a query returns 100
//! rows at most).
//!
//! Two inputs, each a saved response body (`{"results": [[...], ...], "columns": [...]}`):
//! - **surveys**: survey responses are `survey sent` events; the plan's query selects only the event id, time, survey id,
//!   response text and submission id. It never selects `distinct_id` or person properties. One response per submission id.
//! - **funnel**: rows of `step, name, count` (your HogQL, in step order) become one observation with facts
//!   `funnel.<id>.{steps, entered, completed, conversion, max_drop_off, drop_off_step}` for a `flow` rule.
use super::{env_or_placeholder, env_status, feedback_id, feedback_record, Output, Plan};
use crate::redact::Redactor;
use crate::util::round6;
use crate::{invalid, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const ENV: [&str; 3] = ["POSTHOG_HOST", "POSTHOG_PROJECT_ID", "POSTHOG_PERSONAL_API_KEY"];
pub const SURVEY_COLUMNS: [&str; 5] = ["uuid", "timestamp", "survey_id", "response", "submission_id"];
pub const SURVEY_QUERY: &str = "SELECT uuid, timestamp, properties.$survey_id AS survey_id, properties.$survey_response AS response, \
properties.$survey_submission_id AS submission_id FROM events WHERE event = 'survey sent' AND timestamp >= now() - INTERVAL 7 DAY \
ORDER BY timestamp LIMIT 10000";

pub fn plan(query: &str) -> Plan {
    let (configured, env) = env_status(&ENV);
    Plan {
        adapter: "posthog".into(),
        configured,
        env,
        method: "POST".into(),
        url: format!("{}/api/projects/{}/query/", env_or_placeholder("POSTHOG_HOST"), env_or_placeholder("POSTHOG_PROJECT_ID")),
        headers: vec!["Authorization: Bearer ${POSTHOG_PERSONAL_API_KEY}".into(), "Content-Type: application/json".into()],
        body: Some(json!({"query": {"kind": "HogQLQuery", "query": query}, "name": "scoregraph export"})),
        notes: vec![
            "the key needs the Query Read permission; it is read from the environment by the fetcher and never written to a file or a log".into(),
            "POSTHOG_HOST is e.g. https://us.posthog.com, https://eu.posthog.com or a self-hosted origin".into(),
            "an async response carries query_status; poll GET <host>/api/projects/<id>/query/<query id>/ until complete".into(),
        ],
    }
}

/// Rows as objects keyed by column, from `columns` when the response has them, else `expected` in order.
fn rows(body: &Value, expected: &[&str]) -> Result<Vec<serde_json::Map<String, Value>>> {
    let Some(res) = body["results"].as_array() else { return invalid("posthog: response has no `results` array") };
    let cols: Vec<String> = match body["columns"].as_array() {
        Some(c) => c.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect(),
        None => expected.iter().map(|s| s.to_string()).collect(),
    };
    for e in expected {
        if !cols.iter().any(|c| c == e) {
            return invalid(format!("posthog: column `{e}` missing (columns: {})", cols.join(",")));
        }
    }
    res.iter()
        .map(|r| {
            let Some(a) = r.as_array() else { return invalid("posthog: a result row is not an array") };
            Ok(cols.iter().cloned().zip(a.iter().cloned()).collect())
        })
        .collect()
}

pub fn surveys(body: &Value, product: &str) -> Result<Output> {
    let mut out = Output::default();
    let mut seen = BTreeSet::new();
    let mut totals = json!({});
    for r in rows(body, &SURVEY_COLUMNS)? {
        let s = |k: &str| r.get(k).map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())).unwrap_or_default();
        let sub = if s("submission_id").is_empty() || s("submission_id") == "null" { s("uuid") } else { s("submission_id") };
        if !seen.insert(sub.clone()) {
            out.skipped.push(format!("submission {} repeated (a partial response sent again)", crate::util::letter_hash(sub.as_bytes(), 8)));
            continue;
        }
        let text = s("response");
        if text.trim().is_empty() || text == "null" {
            out.skipped.push("empty response".into());
            continue;
        }
        let mut red = Redactor::from_env();
        let text = red.text(&text);
        add_counts(&mut totals, &red);
        out.feedback.push(feedback_record(
            feedback_id("posthog", &sub),
            product,
            "analytics",
            &s("timestamp"),
            text,
            vec![format!("posthog:survey:{}", s("survey_id"))],
            json!({}),
            None,
            "customer",
            &red,
        ));
    }
    out.redaction = totals;
    Ok(out)
}

pub fn funnel(body: &Value, product: &str, version: &str, rule: &str, rule_version: u32, funnel_id: &str) -> Result<Output> {
    let rs = rows(body, &["step", "name", "count"])?;
    if rs.is_empty() {
        return invalid("posthog funnel: no steps");
    }
    let counts: Vec<f64> = rs.iter().map(|r| r["count"].as_f64().unwrap_or(0.0)).collect();
    let entered = counts[0];
    let completed = *counts.last().unwrap_or(&0.0);
    let (mut max_drop, mut drop_step) = (0.0f64, String::new());
    for (i, w) in counts.windows(2).enumerate() {
        if w[0] > 0.0 {
            let d = (w[0] - w[1]) / w[0];
            if d > max_drop {
                max_drop = d;
                drop_step = rs[i + 1]["name"].as_str().unwrap_or("").to_string();
            }
        }
    }
    let facts = json!({"funnel": {funnel_id: {"steps": counts.len(), "entered": entered, "completed": completed,
        "conversion": if entered > 0.0 { round6(completed / entered) } else { 0.0 }, "max_drop_off": round6(max_drop), "drop_off_step": drop_step}}});
    Ok(Output {
        observations: vec![json!({"schema": "observation/1", "product": product, "version": version, "rule": {"id": rule, "version": rule_version},
            "context": {"source": "posthog", "funnel": funnel_id}, "facts": facts, "evidence": [format!("posthog:funnel:{funnel_id}")],
            "probe": {"id": "posthog-funnel", "version": "1"}})],
        ..Default::default()
    })
}

pub(crate) fn add_counts(totals: &mut Value, r: &Redactor) {
    for (k, v) in &r.removed {
        let cur = totals[k].as_u64().unwrap_or(0);
        totals[k] = json!(cur + v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fx(name: &str) -> Value {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/posthog/fixtures").join(name);
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    #[test]
    fn survey_responses_become_redacted_feedback_once_per_submission() {
        let o = surveys(&fx("survey-query-response.json"), "example-web").unwrap();
        assert_eq!(o.feedback.len(), 2, "{:?}", o.skipped);
        assert_eq!(o.skipped.len(), 2);
        let all = serde_json::to_string(&o.feedback).unwrap();
        assert!(!all.contains("@example.com") && !all.contains("555 0123"), "{all}");
        assert!(all.contains("[email:") && all.contains("[phone:"));
        for f in &o.feedback {
            crate::model::Feedback::from_value(f).unwrap();
            assert!(crate::redact::scan(f["text"].as_str().unwrap()).is_empty());
        }
    }

    #[test]
    fn a_funnel_becomes_flow_facts() {
        let o = funnel(&fx("funnel-query-response.json"), "example-web", "a1", "flow.signup.funnel", 1, "signup").unwrap();
        let f = &o.observations[0]["facts"]["funnel"]["signup"];
        assert_eq!(f["entered"], 1000.0);
        assert_eq!(f["conversion"], 0.3);
        assert_eq!(f["drop_off_step"], "verify email");
        crate::model::Observation::from_value(&o.observations[0]).unwrap();
    }

    #[test]
    fn the_plan_names_variables_and_never_holds_a_key() {
        let p = plan(SURVEY_QUERY);
        assert!(p.headers[0].contains("${POSTHOG_PERSONAL_API_KEY}"));
        assert!(p.env.iter().any(|(n, _)| n == "POSTHOG_PERSONAL_API_KEY"));
        assert!(!SURVEY_QUERY.contains("distinct_id") && !SURVEY_QUERY.contains("person"));
        assert!(rows(&json!({"results": [[1]], "columns": ["uuid"]}), &SURVEY_COLUMNS).is_err());
    }
}
