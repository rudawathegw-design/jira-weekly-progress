-- Mailbox store for the FIBPMO dashboard.
-- One row per email (sent or received). Threading is by RFC Message-ID:
-- a reply carries In-Reply-To / References pointing at an id we already have,
-- so we inherit that message's thread_id. Otherwise the message starts a new
-- thread whose id is its own message_id.
CREATE TABLE IF NOT EXISTS messages (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  thread_id    TEXT NOT NULL,           -- groups a conversation
  direction    TEXT NOT NULL,           -- 'out' (we sent) | 'in' (we received)
  message_id   TEXT,                    -- RFC 5322 Message-ID of this email
  in_reply_to  TEXT,                    -- parent Message-ID, if a reply
  refs         TEXT,                    -- full References header
  from_addr    TEXT NOT NULL,
  to_addrs     TEXT NOT NULL,           -- comma-separated
  cc_addrs     TEXT DEFAULT '',         -- comma-separated
  subject      TEXT DEFAULT '',
  html         TEXT DEFAULT '',
  body_text    TEXT DEFAULT '',
  snippet      TEXT DEFAULT '',         -- short plain-text preview
  created_at   TEXT NOT NULL,           -- ISO 8601 UTC
  is_read      INTEGER NOT NULL DEFAULT 0,
  err          TEXT DEFAULT ''          -- non-empty if a send failed
);
CREATE INDEX IF NOT EXISTS idx_msg_thread  ON messages(thread_id, created_at);
CREATE INDEX IF NOT EXISTS idx_msg_created ON messages(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_msg_msgid   ON messages(message_id);
CREATE INDEX IF NOT EXISTS idx_msg_dir     ON messages(direction, created_at DESC);
