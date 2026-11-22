# Adapters

An adapter turns an export into `feedback/1` or `observation/1` records (or claims and stamps for `score`). The engine opens no socket:
an adapter for an API has a **plan** (the exact request a fetcher makes, naming the environment variables that hold its keys, never their
values) and a **parser** for the saved response. Until its variables are set an adapter is **inert**; `scoregraph adapter plan <name>`
says what is missing.

```bash
scoregraph adapter list
scoregraph adapter plan play-reviews                          # the request, and which variables are set (status only)
scoregraph adapter run play-reviews --in page.json --product example-app --dry-run   # counts and redaction, writes nothing
scoregraph adapter run play-reviews --in page.json --product example-app --out fb.jsonl
scoregraph feedback add --db sg.db fb.jsonl                   # the second PII scan; refuses on a hit
```

**PII at the edge.** Every adapter redacts before a record leaves it: emails, phone numbers (8-15 digits, not a date) and known names
(author, nickname and requester fields, then every mention of them in the text) become placeholders such as `[name:kdmgbpac]`. Set
`SCOREGRAPH_REDACT_SALT` so placeholders cannot be reversed by guessing; the record's `redaction` block says whether it was salted and
how much was removed. Name fields themselves are never stored. Free-text names the adapter does not know cannot be found without a model:
that is the product edge's job.

| adapter | input | output | configure later |
|---|---|---|---|
| `comparegraph-export` | `comparegraph export csv --out <dir>` | claims for `score --claims <dir> --claims-repo <repo>` | nothing |
| `gatetrain-stamp` | a folder of `stamp-<sha>.json` | verified stamps for `score --stamps <dir>`; with `--product --rule`, chain observations | nothing |
| `posthog-surveys` | a Query API response | feedback, source `analytics` | `POSTHOG_HOST`, `POSTHOG_PROJECT_ID`, `POSTHOG_PERSONAL_API_KEY` |
| `posthog-funnel` | a Query API response (`step, name, count`) | one observation with funnel facts | same |
| `appstore-reviews` | an App Store Connect customer reviews page | feedback, source `store` | `ASC_APP_ID`, `ASC_ISSUER_ID`, `ASC_KEY_ID`, `ASC_PRIVATE_KEY_PATH` |
| `play-reviews` | a Google Play Developer Reviews page | feedback, source `store` | `PLAY_PACKAGE_NAME`, `GOOGLE_APPLICATION_CREDENTIALS` |
| `tickets` | the generic helpdesk JSON below | feedback, source `ticket` | nothing (map your helpdesk export onto it) |
| `intake` | `intake/1` JSON lines | feedback | nothing |

Each has fixtures under `adapters/<name>/fixtures/` and a test that runs on them.

## comparegraph-export

Reads `claims.csv` (`id,repo,family,feature,verdict,confidence,author,created_at,supersedes_id,note,locations`) and every
`matrix-<family>.csv` (`group,id,tier,weight,<repo>...,prevalence,gap,differentiator`). Per (repo, feature) the latest claim wins: a
superseded claim is dropped, then the latest `created_at`; a matrix cell is used where no claim row exists (`unknown*`, a stale location,
reads as `unknown`). A rule proves a feature by listing its id in `features`.

## gatetrain-stamp

A stamp counts as proof of its `sha` when `v` is 1, it is not `partial` (a run with `--only`/`--skip`), and every step's `rc` is 0. It is
cited by its digest: the sha-256 of the file's bytes. Fixtures are byte-exact (`.gitattributes`), since one changed byte is another digest.

## PostHog (posthog-surveys, posthog-funnel)

Built against PostHog's documented Query API, which a self-hosted instance also serves:

- `POST <POSTHOG_HOST>/api/projects/<POSTHOG_PROJECT_ID>/query/`, `Authorization: Bearer <personal API key>`, body
  `{"query": {"kind": "HogQLQuery", "query": "<HogQL>"}}`. The key needs the **Query Read** permission.
- Limits (project level): 240 requests a minute, 2,400 an hour, 3 concurrent queries; without a `LIMIT` at most 100 rows are returned. A
  long query may answer with `query_status`; poll `GET .../query/<id>/` until complete.
- Survey responses are `survey sent` events. The plan's query selects only `uuid, timestamp, $survey_id, $survey_response,
  $survey_submission_id` from the last 7 days, never `distinct_id` or person properties. One feedback per submission id (a partial
  response sent again is skipped).
- A funnel is your HogQL returning `step, name, count` in step order; it becomes facts
  `funnel.<id>.{steps, entered, completed, conversion, max_drop_off, drop_off_step}` for a `flow` rule, e.g.
  `{"fact": "funnel.signup.conversion", "op": "ge", "value": 0.25}`.

The key is read by the fetcher from the environment and never written to a file or a log; `adapter plan` prints `set` or `unset` only.

## appstore-reviews (Apple App Store Connect)

- `GET https://api.appstoreconnect.apple.com/v1/apps/<ASC_APP_ID>/customerReviews?sort=-createdDate&limit=200`, follow `links.next`.
- Auth: a JWT signed ES256 with an App Store Connect API key (`kid` = key id, `iss` = issuer id, `aud` = `appstoreconnect-v1`, at most
  20 minutes); the `.p8` key stays where `ASC_PRIVATE_KEY_PATH` points.
- Each `customerReviews` item's `rating`, `title`, `body`, `createdDate`, `territory` are read; `reviewerNickname` only redacts the text.
- **Open**: the response shape follows Apple's reference as commonly documented; confirm it on the first real export.

## play-reviews (Google Play Developer Reviews API)

- `GET https://androidpublisher.googleapis.com/androidpublisher/v3/applications/<PLAY_PACKAGE_NAME>/reviews`, follow
  `tokenPagination.nextPageToken`. Auth: an OAuth 2.0 token of a service account with access to the app (`GOOGLE_APPLICATION_CREDENTIALS`
  points at its key file), scope `androidpublisher`.
- **Only reviews with a written comment, and only those created or modified in the last week**, are returned (200 GET requests an hour
  per app). History is kept here instead: poll at least every three days; every page goes to the ledger, which keeps every review
  forever. The feedback id comes from `reviewId` and `lastModified`, so a re-poll is a no-op and an edited review is a new record. Older
  reviews exist only in the Play Console's CSV reports.
- `authorName` only redacts the text; `text` (title and body separated by a tab), `starRating`, `reviewerLanguage`, `appVersionName` are kept.

## tickets

```json
{"tickets": [{"id": "T-1", "subject": "...", "body": "...", "created_at": "2026-01-01T00:00:00Z",
              "requester": {"name": "...", "email": "..."}, "tags": ["billing"], "url": "https://helpdesk.example.com/t/1",
              "surface": "settings/billing"}]}
```

`requester` is never stored (its name redacts the text). A ticket tagged `spam` is skipped; `url` is kept only when it holds no email or
phone number.

## intake

The format a product's own feedback door exports: see `intake/1` in [docs/formats.md](../docs/formats.md#intake1). scoregraph runs no
server; the product stores the records (with its own consent and retention) and hands them over as JSON lines.
