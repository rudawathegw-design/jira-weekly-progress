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
  "template":  "@owner, {action}\n\nCC: @cc",
  "cc_emails": ["someone@fib.iq"],          # optional; from the sheet
  "items": [
    {"key": "FIBTMP-12", "owner": "Jane Doe", "assignee_id": "5b10…", "type": "Sub-task"}
  ]
}

The template may contain these tokens:
  {owner} / @owner  → mention of the CURRENT approval-level reviewer(s); falls
                      back to the assignee when the issue isn't at a level
  {cc}    / @cc      → mentions of every resolved CC person
  {action}          → state-aware phrasing: "please review and approve" at a
                      level, "please share the latest progress update" when
                      In Progress, etc.
  {status}          → the issue's status name (e.g. "Revision Level 1")
  {level}           → "Level N" when at an approval level (else empty)
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
POSTED_KEYS_PATH = os.path.join(ROOT, "data", "temp", "posted_keys.json")  # gitignored
RESULT_PATH      = os.path.join(ROOT, "data", "temp", "post_result.json")   # gitignored

DEFAULT_TEMPLATE = "@owner, {action}\n\nCC: @cc"

# Approval-level routing. The issue's status (e.g. "Revision Level 1") or its
# Approvals field tells which level is pending; @owner then mentions THAT level's
# reviewer(s) — the person who must act now — instead of the assignee.
LEVEL_FIELDS = {1: "customfield_10784", 2: "customfield_10785"}   # Level 1/2 Reviewers
APPROVALS_FIELD = "customfield_10092"                              # "Approvals" (e.g. "Revision Level 1")
LEVEL_RE = re.compile(r"level\s*([0-9]+)", re.I)


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


# ── approval-level context (status → pending level → reviewer mentions) ──────
def _users_field(f, fid):
    """Normalise a Jira user/multi-user custom field to [{id,text}]."""
    val = f.get(fid) or []
    if isinstance(val, dict):
        val = [val]
    out = []
    for u in val:
        if isinstance(u, dict) and u.get("accountId"):
            out.append({"id": u["accountId"], "text": u.get("displayName") or "reviewer"})
    return out


def _issue_context(base_url, headers, key):
    """Fetch an issue's status + level reviewers + assignee.

    Returns {status, level, level_owners:[{id,text}], assignee:{id,text}|None}.
    'level' is the current pending approval level (from the "Revision Level N"
    status, or the Approvals field as a fallback). 'level_owners' are the
    reviewers configured for that level — who should be @mentioned."""
    fields = "status,assignee," + ",".join(LEVEL_FIELDS.values()) + "," + APPROVALS_FIELD
    try:
        r = requests.get(f"{base_url}/rest/api/3/issue/{key}",
                         headers=headers, params={"fields": fields}, timeout=20)
        if r.status_code != 200:
            return None
        f = r.json().get("fields", {}) or {}
    except requests.RequestException as e:
        print(f"  issue context fetch failed for {key}: {e}", file=sys.stderr)
        return None

    st = f.get("status") or {}
    status = st.get("name") or ""
    category = ((st.get("statusCategory") or {}).get("key")) or ""   # new|indeterminate|done
    m = LEVEL_RE.search(status)
    if not m:                                   # fall back to the Approvals field
        appr = f.get(APPROVALS_FIELD) or []
        for o in (appr if isinstance(appr, list) else [appr]):
            s = o.get("value") if isinstance(o, dict) else str(o)
            mm = LEVEL_RE.search(s or "")
            if mm:
                m = mm
                break
    level = int(m.group(1)) if m else None

    a = f.get("assignee") or None
    assignee = ({"id": a["accountId"], "text": a.get("displayName") or "owner"}
                if a and a.get("accountId") else None)
    return {"status": status, "status_norm": status.strip().lower(),
            "category": category, "level": level,
            "level_owners": {1: _users_field(f, LEVEL_FIELDS[1]),
                             2: _users_field(f, LEVEL_FIELDS[2])},
            "assignee": assignee}


# ── PMO comment playbook: per-status professional wording + who to address ───
# target: "assignee" (work statuses) | "level1" | "level2" | "approver".
STATUS_PLAYBOOK = {
    "open":
        ("this task is still in the Open stage and has not been started. Kindly "
         "initiate the work and confirm the planned start and target completion dates.",
         "assignee"),
    "in progress":
        ("kindly provide a progress update on this task — the percentage completed, "
         "any blockers, and the expected completion date.",
         "assignee"),
    "on hold":
        ("this task is currently On Hold. Kindly confirm the reason for the hold and "
         "the expected date to resume.",
         "assignee"),
    "waiting for approval":
        ("this task is awaiting approval. Kindly review the deliverables and provide "
         "your decision, or return it with your comments.",
         "approver"),
    "revision level 1":
        ("this task is pending your Level 1 review. Kindly review and approve, or "
         "return it with the required revisions.",
         "level1"),
    "revision level 2":
        ("this task is pending your Level 2 review. Kindly review and approve, or "
         "return it with the required revisions.",
         "level2"),
    "review complete":
        ("the review for this task has been completed. Kindly proceed with the next "
         "step to move it forward.",
         "assignee"),
    "done":
        ("this task has been completed and marked as Done — thank you for your efforts.",
         "assignee"),
}
DEFAULT_ACTION = "kindly share the latest update on this task."


def _plan_comment(ctx):
    """Decide the professional wording ({action}) and who to @mention for an
    issue, based on its workflow status. Returns (action_text, owner_mentions,
    level_text)."""
    if not ctx:
        return DEFAULT_ACTION, [], ""
    action, target = STATUS_PLAYBOOK.get(ctx.get("status_norm", ""), (DEFAULT_ACTION, "assignee"))
    lo = ctx.get("level_owners") or {}
    assignee = [ctx["assignee"]] if ctx.get("assignee") else []
    if target == "level1":
        owners = lo.get(1) or assignee
    elif target == "level2":
        owners = lo.get(2) or assignee
    elif target == "approver":                 # pending approver: use detected level, else L1
        lvl = ctx.get("level")
        owners = (lo.get(lvl) if lvl in (1, 2) else None) or lo.get(1) or assignee
    else:                                       # assignee-owned work statuses
        owners = assignee
    level_text = f"Level {ctx['level']}" if ctx.get("level") else ""
    return action, owners, level_text


# ── ADF builder ────────────────────────────────────────────────────────────
def _mention_node(account_id, text):
    return {"type": "mention", "attrs": {"id": account_id, "text": f"@{text}"}}


def _text_node(text):
    return {"type": "text", "text": text}


def _build_adf(template, owner_mentions, cc_mentions, status_text="", level_text="", action_text=""):
    """Turn the template into an ADF doc, substituting @owner / {owner} (now the
    current approval-level reviewer(s)) and @cc / {cc} tokens with real mention
    nodes, plus {status} / {level} / {action} text tokens (falling back to
    plain text). {action} is state-aware (review vs in-progress wording)."""
    # Normalise token spellings; substitute the plain-text {status}/{level}/{action}.
    text = template.replace("{owner}", "@owner").replace("{cc}", "@cc")
    text = (text.replace("{status}", status_text or "")
                .replace("{level}", level_text or "")
                .replace("{action}", action_text or ""))

    def render_inline(line):
        """Split a single line into ADF inline nodes, expanding @owner / @cc."""
        nodes = []
        for chunk in re.split(r"(@owner|@cc)", line):
            if chunk == "@owner":
                if owner_mentions:
                    for i, m in enumerate(owner_mentions):
                        if i:
                            nodes.append(_text_node(", "))
                        if m.get("id"):
                            nodes.append(_mention_node(m["id"], m["text"]))
                        else:
                            nodes.append(_text_node(f"@{m.get('text', 'owner')}"))
                else:
                    nodes.append(_text_node("@owner"))
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
        _write_result(0, 0)
        return

    items = queue.get("items") or []
    if not items:
        print("Queue has no items — nothing to post.")
        _write_result(0, 0)
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
        # Resolve who to @mention: the reviewer(s) of the CURRENT approval level
        # (from the issue's "Revision Level N" status / Approvals field). Fall
        # back to the assignee when the issue isn't in a level state.
        ctx = _issue_context(base_url, headers, key)
        status_text = ctx["status"] if ctx else ""
        action_text, owner_mentions, level_text = _plan_comment(ctx)
        if not owner_mentions:                  # fallback to the queued assignee
            if it.get("assignee_id"):
                owner_mentions = [{"id": it["assignee_id"], "text": it.get("owner") or "owner"}]
            elif it.get("owner"):
                m = _resolve_account_id(base_url, headers, it["owner"], cache)
                if m:
                    owner_mentions = [m]

        adf = _build_adf(template, owner_mentions, cc_mentions, status_text, level_text, action_text)
        print(f"  {key}: status={status_text!r} level={ctx['level'] if ctx else None} "
              f"action={action_text!r} → mention {[m['text'] for m in owner_mentions] or ['(none)']}")
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
    # Record which keys posted OK. The workflow's clear step removes exactly
    # these from the LATEST queue — so it never clobbers items queued after this
    # run started, and any failed items stay queued for the next attempt.
    _write_posted_keys([r["key"] for r in results if r["ok"]])
    posted = sum(1 for r in results if r["ok"])
    _write_result(len(results), posted)
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


def _write_result(attempted, posted):
    """Record the run outcome so the workflow can fail loudly (red X) when a
    dispatch posted nothing — an early warning instead of a silent no-op."""
    try:
        os.makedirs(os.path.dirname(RESULT_PATH), exist_ok=True)
        with open(RESULT_PATH, "w", encoding="utf-8") as f:
            json.dump({"attempted": attempted, "posted": posted}, f)
    except OSError as e:
        print(f"Could not write result file: {e}", file=sys.stderr)


def _write_posted_keys(keys):
    """Persist the keys that posted OK to a local (gitignored) file. The
    workflow's clear step reads it after syncing to the latest queue and removes
    exactly these items — a safe read-modify-write that never clobbers newly
    queued work and leaves failed items for the next run."""
    try:
        os.makedirs(os.path.dirname(POSTED_KEYS_PATH), exist_ok=True)
        with open(POSTED_KEYS_PATH, "w", encoding="utf-8") as f:
            json.dump(sorted(set(keys)), f)
    except OSError as e:
        print(f"Could not write posted-keys file: {e}", file=sys.stderr)


if __name__ == "__main__":
    try:
        run()
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(1)
