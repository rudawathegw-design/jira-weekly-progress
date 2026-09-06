-- Attachments for the mailbox. Content stored inline (base64) in D1, capped per
-- file. Inline images (content_id set) are also embedded directly into the
-- message HTML at store time so they render without a separate fetch.
CREATE TABLE IF NOT EXISTS attachments (
  id           TEXT PRIMARY KEY,        -- uuid
  message_row  INTEGER,                 -- messages.id this belongs to
  thread_id    TEXT,
  direction    TEXT,                    -- 'in' | 'out'
  filename     TEXT DEFAULT 'file',
  mime         TEXT DEFAULT 'application/octet-stream',
  size         INTEGER DEFAULT 0,
  is_inline    INTEGER DEFAULT 0,
  content_id   TEXT DEFAULT '',
  content_b64  TEXT DEFAULT '',         -- empty when too large to store
  stored       INTEGER DEFAULT 1,       -- 0 = metadata only (too large)
  created_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_att_msg    ON attachments(message_row);
CREATE INDEX IF NOT EXISTS idx_att_thread ON attachments(thread_id);
