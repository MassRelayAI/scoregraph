//! `comparegraph-export`: reads CompareGraph's `export csv` folder (RFC 4180).
//!
//! - `claims.csv`: `id,repo,family,feature,verdict,confidence,author,created_at,supersedes_id,note,locations`
//! - `matrix-<family>.csv`: `group,id,tier,weight,<repo>...,prevalence,gap,differentiator`; a cell is the latest verdict
//!   (`has | partial | none | unknown`, `unknown*` when its location went stale, empty when unclaimed).
//!
//! A product maps to one CompareGraph repo name (`--claims-repo`). The latest claim per (repo, feature) wins: a claim that a
//! later claim supersedes is dropped, then the latest `created_at`. A matrix cell is used where no claim row exists.
use crate::{invalid, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const CLAIMS_HEADER: [&str; 11] = ["id", "repo", "family", "feature", "verdict", "confidence", "author", "created_at", "supersedes_id", "note", "locations"];

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ClaimRow {
    pub id: String,
    pub repo: String,
    pub family: String,
    pub feature: String,
    pub verdict: String,
    pub confidence: String,
    pub created_at: String,
    pub supersedes_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MatrixRow {
    pub family: String,
    pub id: String,
    pub weight: f64,
    pub cells: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct Claims {
    pub claims: Vec<ClaimRow>,
    pub matrix: Vec<MatrixRow>,
}

fn reader(path: &Path) -> Result<csv::Reader<std::fs::File>> {
    Ok(csv::ReaderBuilder::new().has_headers(true).from_path(path)?)
}

impl Claims {
    /// Load an export folder. `claims.csv` is required; matrices are optional.
    pub fn load(dir: &Path) -> Result<Claims> {
        let cpath = dir.join("claims.csv");
        if !cpath.is_file() {
            return invalid(format!("{}: no claims.csv (run `comparegraph export csv --out <dir>`)", dir.display()));
        }
        let mut rd = reader(&cpath)?;
        let head: Vec<String> = rd.headers()?.iter().map(str::to_string).collect();
        if head != CLAIMS_HEADER {
            return invalid(format!("claims.csv: header must be {}", CLAIMS_HEADER.join(",")));
        }
        let mut claims = vec![];
        for rec in rd.records() {
            let r = rec?;
            let g = |i: usize| r.get(i).unwrap_or("").to_string();
            claims.push(ClaimRow { id: g(0), repo: g(1), family: g(2), feature: g(3), verdict: g(4), confidence: g(5), created_at: g(7), supersedes_id: g(8) });
        }
        let mut names: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("matrix-") && n.ends_with(".csv"))
            .collect();
        names.sort();
        let mut matrix = vec![];
        for n in names {
            let family = n.trim_start_matches("matrix-").trim_end_matches(".csv").to_string();
            let mut rd = reader(&dir.join(&n))?;
            let head: Vec<String> = rd.headers()?.iter().map(str::to_string).collect();
            if head.len() < 7 || head[..4] != ["group", "id", "tier", "weight"] || head[head.len() - 3..] != ["prevalence", "gap", "differentiator"] {
                return invalid(format!("{n}: header must be group,id,tier,weight,<repos>...,prevalence,gap,differentiator"));
            }
            let repos = &head[4..head.len() - 3];
            for rec in rd.records() {
                let r = rec?;
                let weight = r.get(3).unwrap_or("1").parse::<f64>().unwrap_or(1.0);
                let cells = repos.iter().enumerate().map(|(i, repo)| (repo.clone(), r.get(4 + i).unwrap_or("").to_string())).collect();
                matrix.push(MatrixRow { family: family.clone(), id: r.get(1).unwrap_or("").to_string(), weight, cells });
            }
        }
        Ok(Claims { claims, matrix })
    }

    /// feature -> latest verdict for `repo` (matrix cells first, then claim rows override).
    pub fn latest_for(&self, repo: &str) -> BTreeMap<String, String> {
        let mut out: BTreeMap<String, String> = BTreeMap::new();
        for m in &self.matrix {
            if let Some(c) = m.cells.get(repo).filter(|c| !c.is_empty()) {
                out.insert(m.id.clone(), c.trim_end_matches('*').to_string());
            }
        }
        let superseded: BTreeSet<&str> = self.claims.iter().map(|c| c.supersedes_id.as_str()).filter(|s| !s.is_empty()).collect();
        let mut best: BTreeMap<&str, &ClaimRow> = BTreeMap::new();
        for c in self.claims.iter().filter(|c| c.repo == repo && !superseded.contains(c.id.as_str())) {
            let e = best.entry(c.feature.as_str()).or_insert(c);
            if c.created_at > e.created_at {
                *e = c;
            }
        }
        for (f, c) in best {
            out.insert(f.to_string(), c.verdict.clone());
        }
        out
    }

    /// Every feature id the matrices list for a repo column.
    pub fn features_of(&self, repo: &str) -> BTreeSet<String> {
        self.matrix.iter().filter(|m| m.cells.contains_key(repo)).map(|m| m.id.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fixture_export_loads_and_the_latest_claim_wins() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/comparegraph-export/fixtures/export");
        let c = Claims::load(&dir).unwrap();
        let v = c.latest_for("example-web");
        assert_eq!(v["export.csv"], "has");
        assert_eq!(v["share.link"], "partial", "the superseded `has` is dropped");
        assert_eq!(v["search.full-text"], "unknown", "a stale matrix cell reads as unknown");
        assert_eq!(c.features_of("example-web").len(), 4);
        assert!(c.matrix.iter().any(|m| m.weight == 3.0));
    }

    #[test]
    fn a_wrong_header_is_refused() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("claims.csv"), "id,repo\n1,x\n").unwrap();
        assert!(Claims::load(d.path()).unwrap_err().to_string().contains("header"));
        assert!(Claims::load(&d.path().join("missing")).is_err());
    }
}
