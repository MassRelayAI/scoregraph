//! The `scoregraph` binary: a thin command line over `scoregraph-core`.
//!
//! Exit codes: 0 ok · 1 refused (broken rule, broken chain, zero observations, a non-red rule, a missing decision, a privacy hit)
//! · 2 usage or format error · 10-13 gate reasons (see `scoregraph gate --help` and docs/formats.md).
use anyhow::{bail, Context};
use clap::{Args, Parser, Subcommand};
use scoregraph_core::adapters::{self, appstore, comparegraph::Claims, gatetrain, intake, play, posthog, tickets};
use scoregraph_core::feedback;
use scoregraph_core::gate::{self, GateInput};
use scoregraph_core::ledger::{self, obs_key, Ledger};
use scoregraph_core::model::{Observation, Outcome};
use scoregraph_core::ruleset::Ruleset;
use scoregraph_core::score::{self, Input, StampPolicy};
use scoregraph_core::util::{canonical, now_utc, read_records};
use scoregraph_core::{privacy, Error};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "scoregraph", version, about = "Prove and score product features with executable rules; gate regressions on a hash-chained ledger.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run every active rule against its red and green fixtures (red must fail, green must pass).
    Selftest {
        #[arg(long)]
        rules: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate observation/1 files and append them to the ledger.
    Ingest {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        rules: PathBuf,
        #[arg(required = true)]
        files: Vec<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Score one product version under a ruleset.
    Score(ScoreArgs),
    /// Compare head with base; exit 0 or a reason code (10 blocking rule, 11 score drop, 12 coverage drop, 13 gaming).
    Gate {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        product: String,
        #[arg(long)]
        base: String,
        #[arg(long)]
        head: String,
        /// The trusted ruleset (a checkout of the base ref).
        #[arg(long)]
        base_rules: PathBuf,
        /// The ruleset of the head; defaults to the base ruleset.
        #[arg(long)]
        head_rules: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// The ledger: verify, export scores.jsonl, check the anchor.
    Ledger {
        #[command(subcommand)]
        cmd: LedgerCmd,
    },
    /// Feedback records: add, list.
    Feedback {
        #[command(subcommand)]
        cmd: FeedbackCmd,
    },
    /// Rules from feedback: draft, accept (red first), retire (decision only).
    Rule {
        #[command(subcommand)]
        cmd: RuleCmd,
    },
    /// Decision records (the only way to loosen or retire a rule).
    Decision {
        #[command(subcommand)]
        cmd: DecisionCmd,
    },
    /// Input adapters: list, plan (the request a fetcher makes), run (parse a saved response).
    Adapter {
        #[command(subcommand)]
        cmd: AdapterCmd,
    },
    /// Fail when any file holds a deny-listed word, a machine path or a real email.
    PrivacyCheck {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// Print the hash of a word for the deny-list, and check nothing.
        #[arg(long)]
        hash: Option<String>,
    },
}

#[derive(Args)]
struct ScoreArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    rules: PathBuf,
    #[arg(long)]
    product: String,
    #[arg(long)]
    version: String,
    /// A CompareGraph `export csv` folder.
    #[arg(long, requires = "claims_repo")]
    claims: Option<PathBuf>,
    /// The CompareGraph repo name of this product.
    #[arg(long)]
    claims_repo: Option<String>,
    /// A folder of gatetrain stamps: observations without a verified stamp of their own version are unproven.
    #[arg(long)]
    stamps: Option<PathBuf>,
    /// Append the score row to the ledger.
    #[arg(long)]
    append: bool,
    #[arg(long)]
    at: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum LedgerCmd {
    Verify {
        #[arg(long)]
        db: PathBuf,
    },
    /// Write every score row as scores.jsonl (each line chained to the one before).
    Export {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// The committed copy must be a prefix of the current one.
    Anchor {
        /// The committed copy as a file...
        #[arg(long, conflicts_with = "committed_ref")]
        committed: Option<PathBuf>,
        /// ...or as `<ref>:<path>` read with `git show`.
        #[arg(long)]
        committed_ref: Option<String>,
        #[arg(long)]
        current: PathBuf,
    },
}

#[derive(Subcommand)]
enum FeedbackCmd {
    Add {
        #[arg(long)]
        db: PathBuf,
        #[arg(required = true)]
        files: Vec<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
    List {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum RuleCmd {
    Draft {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        feedback: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        out: PathBuf,
    },
    Accept {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        rules: PathBuf,
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        product: String,
        #[arg(long)]
        version: String,
    },
    Retire {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        rules: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        decision: String,
    },
}

#[derive(Subcommand)]
enum DecisionCmd {
    Add {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        rules: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        rule: String,
        /// retire | loosen | promote
        #[arg(long)]
        action: String,
        #[arg(long)]
        why: String,
        #[arg(long)]
        by: String,
    },
}

#[derive(Subcommand)]
enum AdapterCmd {
    List,
    /// The request a fetcher must make, and which environment variables are set (status only).
    Plan {
        name: String,
    },
    /// Parse a saved response or export into records.
    Run {
        name: String,
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long)]
        product: Option<String>,
        #[arg(long)]
        version: Option<String>,
        /// The rule an observation-producing adapter writes for.
        #[arg(long)]
        rule: Option<String>,
        #[arg(long, default_value_t = 1)]
        rule_version: u32,
        #[arg(long)]
        funnel: Option<String>,
        #[arg(long)]
        claims_repo: Option<String>,
        /// Where to write the records (JSON lines). Required unless --dry-run.
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            let code = match e.downcast_ref::<Error>() {
                Some(Error::Refused(_)) => 1,
                _ => 2,
            };
            eprintln!("scoregraph: {e:#}");
            if code == 1 {
                println!("REFUSED");
            }
            ExitCode::from(code)
        }
    }
}

fn print_json(v: &impl serde::Serialize) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn load_rules(dir: &Path) -> anyhow::Result<Ruleset> {
    Ok(Ruleset::load(dir)?)
}

fn write_jsonl(path: &Path, recs: &[Value]) -> anyhow::Result<()> {
    let text: String = recs.iter().map(|r| canonical(r) + "\n").collect();
    std::fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    match cli.cmd {
        Cmd::Selftest { rules, json } => {
            let rs = load_rules(&rules)?;
            let t = rs.self_test();
            if json {
                print_json(&json!({"digest": rs.digest(), "rules": t}))?;
            } else {
                for x in &t {
                    println!("{} {}@{} red={} green={}", if x.ok { "ok    " } else { "BROKEN" }, x.rule, x.version, x.red.as_str(), x.green.as_str());
                }
                println!("ruleset {} ({} active rules)", rs.digest(), t.len());
            }
            rs.require_self_test()?;
            Ok(0)
        }
        Cmd::Ingest { db, rules, files, dry_run } => {
            let rs = load_rules(&rules)?;
            rs.require_self_test()?;
            let mut recs = vec![];
            let mut unknown = 0;
            for f in &files {
                for v in read_records(f)? {
                    let o = Observation::from_value(&v)?;
                    match rs.rules.get(&o.rule.id) {
                        None => unknown += 1,
                        Some(r) => {
                            if o.rule.version > r.version {
                                return Err(Error::Refused(format!("observation of {}@{} but the ruleset has version {}", o.rule.id, o.rule.version, r.version)).into());
                            }
                            if let (Some(f), Some(claimed)) = (&o.facts, o.outcome) {
                                let computed = r.eval(f);
                                if o.rule.version == r.version && claimed != Outcome::Blocked && claimed != computed {
                                    return Err(Error::Refused(format!(
                                        "observation of {} on {}@{}: the probe says {} but its facts give {} under the rule",
                                        o.rule.id, o.product, o.version, claimed.as_str(), computed.as_str()
                                    ))
                                    .into());
                                }
                            }
                        }
                    }
                    recs.push(("observation", obs_key(&o.product, &o.version), serde_json::to_value(&o)?));
                }
            }
            let n = recs.len();
            if !dry_run {
                Ledger::open(&db)?.append_many(&recs)?;
            }
            println!("ingest: {n} observations{} ({unknown} for rules not in the ruleset)", if dry_run { " checked, nothing written (dry run)" } else { " appended" });
            Ok(0)
        }
        Cmd::Score(a) => {
            let rs = load_rules(&a.rules)?;
            let mut l = Ledger::open(&a.db)?;
            l.verify()?;
            let obs = l.observations(&a.product, &a.version)?;
            let claims = a.claims.as_ref().map(|d| Claims::load(d)).transpose()?;
            let verified = match &a.stamps {
                Some(d) => Some(gatetrain::verified(&gatetrain::load_dir(d)?)),
                None => None,
            };
            let s = score::score(&Input {
                ruleset: &rs,
                product: &a.product,
                version: &a.version,
                observations: &obs,
                claims: claims.as_ref().map(|c| (c, a.claims_repo.as_deref().unwrap_or(""))),
                stamps: verified.as_ref().map(|v| StampPolicy { verified: v }),
                at: a.at.clone().unwrap_or_else(now_utc),
            })?;
            if a.append {
                l.append("score", &obs_key(&a.product, &a.version), &s.to_value())?;
            }
            if a.json {
                print_json(&s)?;
            } else {
                print!("{}", score::render(&s));
            }
            Ok(0)
        }
        Cmd::Gate { db, product, base, head, base_rules, head_rules, json } => {
            let l = Ledger::open(&db)?;
            l.verify()?;
            let b = load_rules(&base_rules)?;
            let h = match &head_rules {
                Some(d) => load_rules(d)?,
                None => b.clone(),
            };
            let (bo, ho) = (l.observations(&product, &base)?, l.observations(&product, &head)?);
            let r = gate::gate(&GateInput { product: &product, base: &base, head: &head, base_rules: &b, head_rules: &h, base_obs: &bo, head_obs: &ho })?;
            if json {
                print_json(&r)?;
            } else {
                print!("{}", gate::render(&r));
            }
            Ok(r.exit)
        }
        Cmd::Ledger { cmd } => match cmd {
            LedgerCmd::Verify { db } => {
                let n = Ledger::open(&db)?.verify()?;
                println!("ledger: {n} rows, chain intact");
                Ok(0)
            }
            LedgerCmd::Export { db, out } => {
                let l = Ledger::open(&db)?;
                l.verify()?;
                let text = l.export_scores()?;
                std::fs::write(&out, &text)?;
                println!("scores.jsonl: {} rows -> {}", text.lines().count(), out.display());
                Ok(0)
            }
            LedgerCmd::Anchor { committed, committed_ref, current } => {
                let old = match (committed, committed_ref) {
                    (Some(p), None) => std::fs::read_to_string(&p).with_context(|| format!("cannot read {}", p.display()))?,
                    (None, Some(r)) => {
                        let o = std::process::Command::new("git").args(["show", &r]).output().context("cannot run git")?;
                        if !o.status.success() {
                            // nothing committed yet: an empty history is a prefix of anything
                            if String::from_utf8_lossy(&o.stderr).contains("does not exist") {
                                String::new()
                            } else {
                                bail!("git show {r}: {}", String::from_utf8_lossy(&o.stderr).trim());
                            }
                        } else {
                            String::from_utf8(o.stdout)?
                        }
                    }
                    _ => bail!("give --committed <file> or --committed-ref <ref>:<path>"),
                };
                let new = std::fs::read_to_string(&current).with_context(|| format!("cannot read {}", current.display()))?;
                let (a, b) = ledger::anchor(&old, &new)?;
                println!("anchor: the committed {a} rows are a prefix of the current {b}");
                Ok(0)
            }
        },
        Cmd::Feedback { cmd } => match cmd {
            FeedbackCmd::Add { db, files, dry_run } => {
                let mut recs = vec![];
                for f in &files {
                    recs.extend(read_records(f)?);
                }
                let mut l = Ledger::open(&db)?;
                let r = feedback::add(&mut l, &recs, dry_run)?;
                println!("feedback: {} added, {} already stored{}", r.added.len(), r.already_stored.len(), if dry_run { " (dry run, nothing written)" } else { "" });
                Ok(0)
            }
            FeedbackCmd::List { db, json } => {
                let st = feedback::states(&Ledger::open(&db)?)?;
                if json {
                    print_json(&st)?;
                } else {
                    for s in st.values() {
                        println!("{}  {:<14} {:<9} rules[{}]  {}", s.id, s.status, s.source, s.rules.join(","), s.text.chars().take(60).collect::<String>().replace('\n', " "));
                    }
                    let closed = st.values().filter(|s| s.status == "closed" || s.status == "fixed").count();
                    println!("{} feedback, {} fixed or closed", st.len(), closed);
                }
                Ok(0)
            }
        },
        Cmd::Rule { cmd } => match cmd {
            RuleCmd::Draft { db, feedback: fb, id, owner, out } => {
                let mut l = Ledger::open(&db)?;
                let d = feedback::draft(&mut l, &fb, &id, &owner, &now_utc())?;
                std::fs::write(&out, serde_json::to_string_pretty(&d)? + "\n")?;
                println!("draft {id} -> {} (fill check, red and green; accept refuses it until it is red on the product)", out.display());
                Ok(0)
            }
            RuleCmd::Accept { db, rules, draft, product, version } => {
                let mut l = Ledger::open(&db)?;
                let d: Value = serde_json::from_str(&std::fs::read_to_string(&draft)?).with_context(|| format!("{}", draft.display()))?;
                let a = feedback::accept(&mut l, &rules, &d, &product, &version, &now_utc())?;
                println!("accepted {}@{}: red on {} ({} of {} observations fail) -> {}", a.rule, a.version, a.red_on, a.failing, a.measured, a.path);
                Ok(0)
            }
            RuleCmd::Retire { db, rules, id, decision } => {
                let mut l = Ledger::open(&db)?;
                feedback::retire(&mut l, &rules, &id, &decision, &now_utc())?;
                println!("retired {id} by decision {decision}");
                Ok(0)
            }
        },
        Cmd::Decision { cmd: DecisionCmd::Add { db, rules, id, rule, action, why, by } } => {
            let mut l = Ledger::open(&db)?;
            let d = json!({"schema": "decision/1", "id": id, "rule": rule, "action": action, "why": why, "decided_by": by, "decided_at": now_utc()});
            let d = feedback::add_decision(&mut l, &rules, &d)?;
            println!("decision {} ({:?} {}) recorded", d.id, d.action, d.rule);
            Ok(0)
        }
        Cmd::Adapter { cmd } => adapter(cmd),
        Cmd::PrivacyCheck { root, hash } => Ok(match privacy::run(&root, hash.as_deref()) {
            0 => 0,
            1 => 1,
            _ => 2,
        }),
    }
}

fn read_json(p: &Path) -> anyhow::Result<Value> {
    serde_json::from_str(&std::fs::read_to_string(p).with_context(|| format!("cannot read {}", p.display()))?).with_context(|| format!("{} is not JSON", p.display()))
}

fn adapter(cmd: AdapterCmd) -> anyhow::Result<i32> {
    match cmd {
        AdapterCmd::List => {
            for n in adapters::NAMES {
                println!("{n}");
            }
            Ok(0)
        }
        AdapterCmd::Plan { name } => {
            let p = match name.as_str() {
                "posthog-surveys" => posthog::plan(posthog::SURVEY_QUERY),
                "posthog-funnel" => posthog::plan("<your funnel HogQL returning columns step, name, count in step order>"),
                "appstore-reviews" => appstore::plan(),
                "play-reviews" => play::plan(),
                "comparegraph-export" | "gatetrain-stamp" | "tickets" | "intake" => {
                    println!("{name}: a file adapter; nothing to fetch, nothing to configure (scoregraph adapter run {name} --in <path>)");
                    return Ok(0);
                }
                _ => bail!("unknown adapter {name} (scoregraph adapter list)"),
            };
            print_json(&p)?;
            if !p.configured {
                let missing: Vec<&str> = p.env.iter().filter(|(_, s)| s == "unset").map(|(n, _)| n.as_str()).collect();
                println!("{name}: inert until configured; unset: {}", missing.join(", "));
            }
            Ok(0)
        }
        AdapterCmd::Run { name, input, product, version, rule, rule_version, funnel, claims_repo, out, dry_run } => {
            let need = |o: &Option<String>, f: &str| o.clone().with_context(|| format!("{name} needs --{f}"));
            let output = match name.as_str() {
                "comparegraph-export" => {
                    let c = Claims::load(&input)?;
                    let repo = need(&claims_repo, "claims-repo")?;
                    let v = c.latest_for(&repo);
                    print_json(&json!({"repo": repo, "claims": c.claims.len(), "matrix_rows": c.matrix.len(), "features": c.features_of(&repo).len(), "latest": v}))?;
                    return Ok(0);
                }
                "gatetrain-stamp" => {
                    let st = gatetrain::load_dir(&input)?;
                    let mut o = adapters::Output::default();
                    if let (Some(p), Some(r)) = (&product, &rule) {
                        o.observations = st.iter().map(|s| gatetrain::observation(s, p, r, rule_version)).collect();
                    }
                    o.skipped = st.iter().filter_map(|s| s.refused.as_ref().map(|w| format!("stamp {}: {w}", &s.digest[..12]))).collect();
                    o.redaction = json!({"stamps": st.len(), "verified": gatetrain::verified(&st).len()});
                    o
                }
                "posthog-surveys" => posthog::surveys(&read_json(&input)?, &need(&product, "product")?)?,
                "posthog-funnel" => posthog::funnel(&read_json(&input)?, &need(&product, "product")?, &need(&version, "version")?, &need(&rule, "rule")?, rule_version, &need(&funnel, "funnel")?)?,
                "appstore-reviews" => appstore::parse(&read_json(&input)?, &need(&product, "product")?)?,
                "play-reviews" => play::parse(&read_json(&input)?, &need(&product, "product")?)?,
                "tickets" => tickets::parse(&read_json(&input)?, &need(&product, "product")?)?,
                "intake" => intake::parse(&read_records(&input)?)?,
                _ => bail!("unknown adapter {name} (scoregraph adapter list)"),
            };
            let summary = json!({"adapter": name, "feedback": output.feedback.len(), "observations": output.observations.len(), "skipped": output.skipped, "redaction": output.redaction, "dry_run": dry_run});
            if dry_run {
                print_json(&summary)?;
                return Ok(0);
            }
            let Some(out) = out else { bail!("give --out <file.jsonl>, or --dry-run") };
            let recs: Vec<Value> = output.feedback.into_iter().chain(output.observations).collect();
            write_jsonl(&out, &recs)?;
            print_json(&summary)?;
            println!("{name}: {} records -> {}", recs.len(), out.display());
            Ok(0)
        }
    }
}
