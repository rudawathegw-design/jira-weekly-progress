"""
post_comments.py
Posts comments to Jira issues from a queue file the dashboard writes.

Flow:
  1. The dashboard (docs/index.html) lets the user pick overdue issues by type
     (Sub-task / Task / Story / Epic …), preview the comment, deselect any to
     exclude, then commits  data/comment_queue.json  to the repo and triggers
     the  comments.yml  workflow.
  2. This script reads that queue, builds an Atlassian-Document-Format (ADF)
     comment for each issue — turning  @owner  into a real Jira mention (via the
     issue's assignee accountId) and  CC: @someone  into mentions resolved from
     data/email_recipients.json (the "sheet") — and POSTs it to Jira.
  3. It writes  data/comment_log.json  (what was posted / failed) and clears the
     queue so the same batch never double-posts.

Queue format (data/comment_queue.json):
{
  "created":   "2026-06-04T10:00:00Z",
  "template":  "@owner, what is the update on this task?\n\nCC: @cc",
  "cc_emails": ["someone@fib.iq"],          # optional; from the sheet
  "items": [
    {"key": "FIBTMP-12", "owner": "Jane Doe", "assignee_id": "5b10…", "type": "Sub-task"}
  ]
}

The template may contain two tokens:
  {owner} / @owner  → mention of the issue assignee
  {cc}    / @cc      → mentions of every resolved CC person
"""

import os
import re
import sys
import json
import base64
import requests

ROOT        = os.path.join(os.path.dirname(__file__), "..")
QUEUE_PATH  = os.path.join(ROOT, "data", "comment_queue.json")
LOG_PATH    = os.path.join(ROOT, "data", "comment_log.json")
SHEET_PATH  = os.path.join(ROOT, "data", "email_recipients.json")

DEFAULT_TEMPLATE = "@owner, what is the update on this task?\n\nCC: @cc"


# ── auth ───────────────────────────────────────────────────────────────────
def _headers(email, token):
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Basic {auth}",
    }


# ── user lookup (email → accountId) ────────────────────────────────────────
def _resolve_account_id(base_url, headers, query, cache):
    """Resolve an email or display name to a Jira accountId (cached)."""
    query = (query or "").strip()
    if not query:
        return None
    if query in cache:
        return cache[query]
    try:
        r = requests.get(
            f"{base_url}/rest/api/3/user/search",
            headers=headers, params={"query": query, "maxResults": 1}, timeout=20,
        )
        if r.status_code == 200 and r.json():
            acc = r.json()[0]
            cache[query] = {"id": acc.get("accountId"), "text": acc.get("displayName") or query}
            return cache[query]
    except requests.RequestException as e:
        print(f"  user lookup failed for {query!r}: {e}", file=sys.stderr)
    cache[query] = None
    return None


# ── ADF builder ────────────────────────────────────────────────────────────
def _mention_node(account_id, text):
    return {"type": "mention", "attrs": {"id": account_id, "text": f"@{text}"}}


def _text_node(text):
    return {"type": "text", "text": text}


def _build_adf(template, owner_mention, cc_mentions):
    """Turn the template into an ADF doc, substituting @owner / {owner} and
    @cc / {cc} tokens with real mention nodes (falling back to plain text)."""
    # Normalise the two token spellings to a single sentinel we can split on.
    text = template.replace("{owner}", "@owner").replace("{cc}", "@cc")

    def render_inline(line):
        """Split a single line into ADF inline nodes, expanding @owner / @cc."""
        nodes = []
        for chunk in re.split(r"(@owner|@cc)", line):
            if chunk == "@owner":
                if owner_mention and owner_mention.get("id"):
                    nodes.append(_mention_node(owner_mention["id"], owner_mention["text"]))
                else:
                    nodes.append(_text_node(f"@{(owner_mention or {}).get('text', 'owner')}"))
            elif chunk == "@cc":
                if cc_mentions:
                    for i, m in enumerate(cc_mentions):
                        if i:
                            nodes.append(_text_node(", "))
                        nodes.append(_mention_node(m["id"], m["text"]))
                else:
                    nodes.append(_text_node("@someone"))
            elif chunk:
                nodes.append(_text_node(chunk))
        return nodes or [_text_node("")]

    paragraphs = []
    for line in text.split("\n"):
        if line.strip() == "":
            paragraphs.append({"type": "paragraph", "content": []})
        else:
            paragraphs.append({"type": "paragraph", "content": render_inline(line)})

    return {"type": "doc", "version": 1, "content": paragraphs or [{"type": "paragraph", "content": []}]}


# ── main ───────────────────────────────────────────────────────────────────
def run():
    email    = os.environ.get("JIRA_EMAIL", "")
    token    = os.environ.get("JIRA_API_TOKEN", "")
    base_url = os.environ.get("JIRA_BASE_URL", "https://fibtask.atlassian.net").rstrip("/")
    if not email or not token:
        print("ERROR: JIRA_EMAIL and JIRA_API_TOKEN must be set.", file=sys.stderr)
        sys.exit(1)

    # Queue is encrypted at rest (comment_queue.json.enc) — it carries owner
    # names + issue keys. load_store decrypts (with SITE_PASSWORD) and falls
    # back to a legacy plaintext queue if present.
    from crypto_store import load_store
    queue = load_store(QUEUE_PATH, default=None)
    if not queue:
        print("No comment queue — nothing to post.")
        return

    items = queue.get("items") or []
    if not items:
        print("Queue has no items — nothing to post.")
        _clear_queue()
        return

    template  = queue.get("template") or DEFAULT_TEMPLATE
    cc_emails = queue.get("cc_emails")
    if cc_emails is None:                       # fall back to the sheet
        cc_emails = _load_sheet()

    headers = _headers(email, token)
    cache   = {}

    # Resolve CC people once (shared across every comment).
    cc_mentions = []
    for addr in cc_emails:
        m = _resolve_account_id(base_url, headers, addr, cache)
        if m and m.get("id"):
            cc_mentions.append(m)
        else:
            print(f"  CC not resolved (skipped from mention): {addr}")

    results = []
    print(f"Posting comments to {len(items)} issue(s)…")
    for it in items:
        key = (it.get("key") or "").strip()
        if not key:
            continue
        owner_mention = None
        if it.get("assignee_id"):
            owner_mention = {"id": it["assignee_id"], "text": it.get("owner") or "owner"}
        elif it.get("owner"):                   # no accountId on record → look it up
            owner_mention = _resolve_account_id(base_url, headers, it["owner"], cache)

        adf = _build_adf(template, owner_mention, cc_mentions)
        try:
            r = requests.post(
                f"{base_url}/rest/api/3/issue/{key}/comment",
                headers=headers, data=json.dumps({"body": adf}), timeout=30,
            )
            ok = r.status_code in (200, 201)
            results.append({"key": key, "ok": ok, "status": r.status_code,
                            "error": None if ok else r.text[:300]})
            print(f"  {key}: {'✓ posted' if ok else f'✗ HTTP {r.status_code} — {r.text[:120]}'}")
        except requests.RequestException as e:
            results.append({"key": key, "ok": False, "status": None, "error": str(e)})
            print(f"  {key}: ✗ {e}", file=sys.stderr)

    _write_log(queue, results)
    _clear_queue()
    posted = sum(1 for r in results if r["ok"])
    print(f"Done. {posted}/{len(results)} comment(s) posted.")


def _load_sheet():
    # Recipients sheet is encrypted at rest (email_recipients.json.enc). Needs
    # SITE_PASSWORD; if unavailable, fall back to no CC rather than failing.
    try:
        from crypto_store import load_store
        data = load_store(SHEET_PATH, default=[])
        return data if isinstance(data, list) else []
    except Exception as e:
        print(f"  CC sheet unreadable (no CC applied): {e}", file=sys.stderr)
        return []


def _write_log(queue, results):
    log = {
        "posted_at": queue.get("created"),
        "template":  queue.get("template"),
        "results":   results,
    }
    try:
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(log, f, indent=2)
            f.write("\n")
    except OSError as e:
        print(f"Could not write comment_log.json: {e}", file=sys.stderr)


def _clear_queue():
    """Empty the queue so the same batch never double-posts. Writes an
    encrypted empty queue and removes any legacy plaintext."""
    try:
        from crypto_store import save_store
        save_store(QUEUE_PATH, {"items": []})   # → comment_queue.json.enc
    except Exception as e:
        print(f"Could not clear comment queue: {e}", file=sys.stderr)


if __name__ == "__main__":
    try:
        run()
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(1)
