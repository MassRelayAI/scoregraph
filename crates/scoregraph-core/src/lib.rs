//! scoregraph core: proves and scores product features with executable rules.
//!
//! The engine never opens a browser, a network socket or a model. It reads files (observations, rules, feedback, adapter
//! exports), evaluates rules over facts, scores, appends to a hash-chained ledger and gates. Probes and fetchers live outside.
//!
//! Map of the crate:
//! - [`check`]: the small predicate language a rule is written in, evaluated over facts.
//! - [`model`]: the versioned record formats (`observation/1`, `rule/1`, `feedback/1`, `decision/1`, `score/1`).
//! - [`ruleset`]: a rule directory, its digest and the self-test every run starts with.
//! - [`score`]: family scores, floor, coverage, proven share, overclaims, noise bands.
//! - [`gate`]: base against head, anti-gaming included; exit codes for a CI step.
//! - [`ledger`]: the append-only SQLite chain and the exported `scores.jsonl` with its anchor check.
//! - [`feedback`]: feedback intake, red-first rule acceptance, retirement by decision only.
//! - [`redact`]: PII redaction at the edge and the refusing scan on ingest.
//! - [`adapters`]: input adapters, inert until configured.
//! - [`privacy`]: the repository deny-list check.
pub mod adapters;
pub mod check;
pub mod feedback;
pub mod gate;
pub mod ledger;
pub mod model;
pub mod privacy;
pub mod redact;
pub mod ruleset;
pub mod score;
pub mod util;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A record or a file does not follow its format.
    #[error("invalid: {0}")]
    Invalid(String),
    /// The engine refuses to go on (a broken rule, a broken chain, a non-red rule, a missing decision).
    #[error("refused: {0}")]
    Refused(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("csv: {0}")]
    Csv(#[from] csv::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn invalid<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Invalid(msg.into()))
}

pub(crate) fn refused<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Refused(msg.into()))
}
