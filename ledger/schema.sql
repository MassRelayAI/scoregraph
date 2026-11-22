-- scoregraph ledger: ONE append-only, hash-chained table. Nothing is updated in place and nothing is deleted.
-- Every kind of record shares the chain, so an edit anywhere breaks every later hash.
--   hash = sha256_hex(prev || body)       prev of the first row = 64 zeros
-- `body` is canonical JSON (sorted keys, no whitespace). The engine verifies the whole chain before every write and refuses
-- to append to a broken one.

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
  seq   INTEGER PRIMARY KEY,      -- 1, 2, 3 ... without gaps
  kind  TEXT NOT NULL,            -- observation | score | feedback | feedback-event | rule-event | decision
  key   TEXT NOT NULL,            -- product@version, a feedback id or a rule id
  body  TEXT NOT NULL,            -- canonical JSON of the record
  prev  TEXT NOT NULL,            -- hash of row seq-1
  hash  TEXT NOT NULL             -- sha256_hex(prev || body)
);

CREATE INDEX IF NOT EXISTS entries_kind_key ON entries (kind, key);

CREATE TRIGGER IF NOT EXISTS entries_no_update BEFORE UPDATE ON entries
BEGIN SELECT RAISE(ABORT, 'entries is append-only: UPDATE refused'); END;

CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries
BEGIN SELECT RAISE(ABORT, 'entries is append-only: DELETE refused'); END;
