# Changelog

## 0.1.0 (unreleased)

Engine v0.

- Formats `observation/1`, `rule/1`, `feedback/1`, `decision/1`, `score/1`, `intake/1`, with JSON Schemas.
- A three-valued check language over facts; the rule self-test on every run.
- Scores per family with floor, coverage, noise bands from repeats, a claim audit against CompareGraph (proven, overclaims).
- The gate: exit 10 blocking rule regressed, 11 score drop beyond noise, 12 coverage drop, 13 loosening without a decision; the head
  scored under the base ruleset too.
- One append-only hash-chained SQLite ledger; `scores.jsonl` with an anchor check.
- Feedback to rule, red first; retirement by decision only.
- Adapters: comparegraph-export, gatetrain-stamp, posthog-surveys, posthog-funnel, appstore-reviews, play-reviews, tickets, intake; PII
  redaction at the edge and a refusing scan on ingest.
- `privacy-check`: deny-listed words (hashes only), machine paths, real emails.
