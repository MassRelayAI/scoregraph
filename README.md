# scoregraph

**Prove and score what a product claims, with executable rules, and refuse changes that make it worse.**

[CompareGraph](https://github.com/MassRelayAI/comparegraph) records which features products *claim*. scoregraph *proves* them: every
rule is a versioned check with a red and a green fixture, probes record what they saw as observations, and the engine scores each
product version per family (feature, UI, navigation, flows, quality, judged), keeps an append-only hash-chained ledger pinned to commits,
turns feedback into permanent red-first rules, and gates any change that lowers a score beyond measured noise.

> Status: early (engine v0). The engine, formats, ledger, gate and adapters are here; browser and mobile probes come next.
>
> Name: other, unrelated public projects are also called scoregraph. This one has no affiliation with them.

## Why

| what goes wrong | what scoregraph does |
|---|---|
| A feature is "done" because a file exists. | A claim counts as **proven** only when a rule for it passes on the running product. A `has` with a failing proof is an **overclaim**. |
| A check never seen to fail is trusted. | **Self-test on every run**: each rule must fail its red fixture and pass its green one, or the run refuses. |
| A complaint is fixed, then quietly comes back. | **Feedback -> rule, red first**: a rule is accepted only when it fails on the product today; it stays forever and the gate blocks its regression. |
| Scores are compared across different rules or noisy runs. | Scores carry their **ruleset digest**; repeats give a **noise band**; a drop counts only beyond it. |
| A change edits the rule it breaks. | The head is also scored under the **base** ruleset; loosening or retiring a rule needs a **decision already on the base**. |
| History is rewritten. | One **append-only, hash-chained** SQLite ledger whose committed head must still be held; the exported `scores.jsonl` must keep the committed copy as a prefix. |

## Install

Rust 1.89 or newer. No server, no database service: the ledger is one SQLite file compiled in. The engine opens no network socket.

```bash
git clone https://github.com/MassRelayAI/scoregraph
cd scoregraph
cargo install --path crates/scoregraph-cli    # puts `scoregraph` in ~/.cargo/bin
scoregraph --version
```

## Five minutes with the example

```bash
R=rulesets/example
scoregraph selftest --rules $R                                     # 7 rules, each red on red and green on green
scoregraph ingest --db sg.db --rules $R $R/observations/base-a1.jsonl $R/observations/head-b2.jsonl
scoregraph score  --db sg.db --rules $R --product example-web --version a1 \
  --claims adapters/comparegraph-export/fixtures/export --claims-repo example-web --append
scoregraph score  --db sg.db --rules $R --product example-web --version b2 --append
scoregraph gate   --db sg.db --product example-web --base a1 --head b2 --base-rules $R   # exit 10: a blocking rule regressed
scoregraph ledger verify --db sg.db
scoregraph ledger export --db sg.db --out scores.jsonl
```

## Commands

| command | does |
|---|---|
| `selftest --rules <dir>` | every active rule against its red and green fixtures; exit 1 if any is broken |
| `ingest --db --rules <files>` | validate `observation/1` records and append them; refuses a probe outcome that contradicts its own facts |
| `score --db --rules --product --version` | family scores, floor, coverage, noise band; `--claims` adds proven % and overclaims; `--stamps` requires gatetrain stamps; `--append` writes the row |
| `gate --db --product --base --head --base-rules [--head-rules]` | exit 0, or 10 blocking rule regressed, 11 score drop beyond noise, 12 coverage drop, 13 rule loosened or retired without a decision |
| `ledger verify \| head \| export \| anchor` | recompute the chain (`--anchor` also requires the committed head); write the head to commit; write `scores.jsonl`; check the committed copy (`--committed-ref origin/main:scores.jsonl`) is a prefix |
| `feedback add \| list` | store redacted `feedback/1` (a record holding an email or a phone number is refused); show each one's status |
| `rule draft \| accept \| retire` | a rule skeleton from feedback; accept only when red on the named product version; retire only by decision |
| `decision add` | a `decision/1` record, the only way to loosen or retire a rule |
| `adapter list \| plan \| run` | input adapters: what to fetch (key names only), and parsing a saved response, with `--dry-run` |
| `privacy-check` | no deny-listed word, machine path or real email in any file |

Exit codes everywhere: 0 ok, 1 refused, 2 usage or format error, 10-13 gate reasons.

## As a gatetrain step

```toml
[[step]]
name = "score-gate"
tier = "slow"
needs = ["probes"]
run = "scoregraph gate --db ledger.db --product example-web --base $BASE_SHA --head $HEAD_SHA --base-rules ../base/rulesets/example --head-rules rulesets/example"
```

The probes step writes observations citing the run's stamp; `score --stamps <out>` then counts only observations proven by a green,
full, clean-tree stamp of their own commit.

## Documents

- [Design](docs/design.md): what is scored, the score, noise, the gate, anti-gaming, feedback to rule, the judge loop.
- [Formats](docs/formats.md): `observation/1`, `rule/1`, `feedback/1`, `decision/1`, `score/1`, `intake/1`, the check language, the ledger.
- [Adapters](adapters/README.md): CompareGraph, gatetrain, PostHog, App Store Connect, Google Play, tickets, intake; how each is configured.
- JSON Schemas: [`schemas/`](schemas/).

## Roadmap

1. Engine v0: formats, self-test, score, gate, ledger, feedback, adapters (this release).
2. Probes: web (Playwright structure facts, axe-core, target size, responsive), navigation walker, flows, mobile (Maestro), repository checks.
3. The judge loop: pairwise judging against fixed references with order swap, calibration and drift control; advisory until promoted.
4. Comparators: open-source products booted locally; public pages of closed products (structure only).

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
