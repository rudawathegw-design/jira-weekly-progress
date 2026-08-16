"""
accountability.py
Answers one question per issue: **who is actually on the hook right now?**

The assignee owns *delivery*. But the moment a task moves to "Revision Level 1"
or "Revision Level 2", the assignee has already handed off — the person who must
act is that level's reviewer. Counting such a task (especially an overdue one)
against the assignee misattributes the delay and sends the follow-up to the
wrong person.

Resolution chain (first hit wins):
  1. A *pending* entry in the "Approvals" field (customfield_10092). This is the
     most precise source: it reflects who still owes a decision right now, and
     names the level ("Revision Level 1"/"Revision Level 2").
  2. The level implied by the status name → that level's Reviewers field
     (customfield_10784 / _10785).
  3. "Waiting For Approval" → the REPORTER. By this point the level reviewers
     have already signed off ("Revision Level 1" → "Review Complete") and a Jira
     automation has moved the task on; what remains is the requester's own
     acceptance. Neither reviewer nor assignee can clear this stage.
  4. Fall back to the assignee, flagged `unresolved` so the UI can surface the
     governance gap ("in review but no reviewer configured") instead of quietly
     blaming the assignee.

Where a level has SEVERAL reviewers, the first is the *primary* and carries the
count; the rest are returned as `co_owners`. This keeps per-person totals summing
exactly to the team total, so team completion %% stays trustworthy.

Verified against the live FIBTMP project: of the 26 issues at a review status,
25 resolve to a named reviewer; 1 (no reviewer configured) falls to rule 4.
"""

import re

# ── Jira field ids (verified present on this instance) ──────────────────────
LEVEL_FIELDS    = {1: "customfield_10784", 2: "customfield_10785"}   # Level 1/2 Reviewers
APPROVALS_FIELD = "customfield_10092"                                # Approvals (sd-approvals)

# customfield_10520 is "Involved Users" — a general participant list, NOT an
# approver field. It is deliberately absent from the resolution chain below:
# being involved in a task does not make you the person who owes the decision.
# calculate.py still carries it through as `involved_name` for the exports.
INVOLVED_FIELD = "customfield_10520"

LEVEL_RE = re.compile(r"level\s*([0-9]+)", re.I)

# ── roles ───────────────────────────────────────────────────────────────────
ROLE_ASSIGNEE = "assignee"
ROLE_LEVEL1   = "level1"
ROLE_LEVEL2   = "level2"
ROLE_APPROVER = "approver"      # awaiting approval, level not identified
ROLE_REPORTER = "reporter"      # awaiting the requester's own sign-off

ROLE_LABELS = {
    ROLE_ASSIGNEE: "Assignee",
    ROLE_LEVEL1:   "Level 1 Reviewer",
    ROLE_LEVEL2:   "Level 2 Reviewer",
    ROLE_APPROVER: "Approver",
    ROLE_REPORTER: "Reporter",
}

# ── attribution modes ───────────────────────────────────────────────────────
MODE_ASSIGNEE    = "assignee"      # classic: everything counts to the assignee
MODE_ACCOUNTABLE = "accountable"   # default: reviewer holds it while in review
MODE_REVIEWER    = "reviewer"      # review-bottleneck board: in-review work only
VALID_MODES = (MODE_ASSIGNEE, MODE_ACCOUNTABLE, MODE_REVIEWER)

UNASSIGNED = "Unassigned"

# ── status → reporting bucket ───────────────────────────────────────────────
# The Excel layout has four buckets. Historically any status that did not match
# "progress"/"wait"/"approv" fell into Open — which silently dumped every
# "Revision Level 1" task (22 of them) into Open. These defaults fix that while
# keeping the Excel column shape identical. The dashboard exposes this map in a
# Status Mapping panel, so the mapping is configurable rather than hard-coded.
BUCKET_OPEN      = "Open"
BUCKET_PROGRESS  = "In Progress"
BUCKET_WFA       = "Waiting For Approval"
BUCKET_COMPLETED = "Completed"
BUCKETS = (BUCKET_OPEN, BUCKET_PROGRESS, BUCKET_WFA, BUCKET_COMPLETED)

DEFAULT_STATUS_BUCKETS = {
    "open":                 BUCKET_OPEN,
    "on hold":              BUCKET_OPEN,
    "in progress":          BUCKET_PROGRESS,
    "review complete":      BUCKET_PROGRESS,
    "waiting for approval": BUCKET_WFA,
    "revision level 1":     BUCKET_WFA,
    "revision level 2":     BUCKET_WFA,
    "done":                 BUCKET_COMPLETED,
    "available":            BUCKET_COMPLETED,
}

# Statuses where the ball is with a reviewer, not the assignee.
REVIEW_STATUSES = {"waiting for approval", "revision level 1", "revision level 2"}


# ── small helpers ───────────────────────────────────────────────────────────
def status_name(issue) -> str:
    return ((issue.get("fields") or {}).get("status") or {}).get("name") or "Unknown"


def status_norm(issue) -> str:
    return status_name(issue).strip().lower()


def is_done(issue) -> bool:
    fields = issue.get("fields") or {}
    st = fields.get("status") or {}
    if (st.get("name") or "").strip().lower() == "available":
        return True
    return ((st.get("statusCategory") or {}).get("key")) == "done"


def bucket_for(issue, status_map=None) -> str:
    """Map a Jira status to one of the four reporting buckets."""
    if is_done(issue):
        return BUCKET_COMPLETED
    name = status_norm(issue)
    mapping = status_map or DEFAULT_STATUS_BUCKETS
    hit = mapping.get(name)
    if hit in BUCKETS:
        return hit
    # Unknown status → keep the old heuristic so a newly added Jira status still
    # lands somewhere sensible instead of silently becoming Open.
    if "progress" in name:
        return BUCKET_PROGRESS
    if "wait" in name or "approv" in name or "revision" in name or "review" in name:
        return BUCKET_WFA
    return BUCKET_OPEN


def is_review_status(issue, status_map=None) -> bool:
    """True when the issue's STATUS is one that can involve an approval.

    Note the difference from ``resolve_accountable(...)["in_review"]``:

      * this function is about the status label — it decides which reporting
        bucket the issue lands in;
      * ``in_review`` is about whether a named person actually owes a decision.

    They deliberately disagree for "Waiting For Approval" with no approver set:
    the status belongs in the approval bucket, but nobody has been asked to
    approve, so the assignee still owns the work. Always use ``in_review`` when
    the question is "who do I chase?".
    """
    if is_done(issue):
        return False
    name = status_norm(issue)
    if name in REVIEW_STATUSES:
        return True
    # Respect a custom mapping: anything the admin mapped into the approval
    # bucket counts as in-review for attribution purposes too.
    if status_map and status_map.get(name) == BUCKET_WFA:
        return True
    return False


def _users(fields, field_id):
    """Normalise a Jira user / multi-user picker field to [{id, name}].

    Tolerates both the raw Jira shape and the slimmed shape the Cloudflare
    Worker returns (see worker/github-proxy.js::slimUser).
    """
    val = fields.get(field_id) or []
    if isinstance(val, dict):
        val = [val]
    out = []
    for u in val:
        if isinstance(u, dict) and u.get("accountId"):
            out.append({"id": u["accountId"], "name": u.get("displayName") or "Reviewer"})
    return out


def _pending_approvals(fields):
    """Pending entries of the sd-approvals field → [(level, [{id,name}])]."""
    val = fields.get(APPROVALS_FIELD) or []
    if isinstance(val, dict):
        val = [val]
    out = []
    for a in val:
        if not isinstance(a, dict):
            continue
        if (a.get("finalDecision") or "").strip().lower() != "pending":
            continue
        m = LEVEL_RE.search(a.get("name") or "")
        level = int(m.group(1)) if m else None
        people = []
        for x in a.get("approvers") or []:
            # Raw Jira nests the user under "approver"; the slimmed Worker shape
            # is already the user object.
            u = x.get("approver") if isinstance(x, dict) and "approver" in x else x
            if isinstance(u, dict) and u.get("accountId"):
                people.append({"id": u["accountId"], "name": u.get("displayName") or "Reviewer"})
        if people:
            out.append((level, people))
    return out


def _assignee(fields):
    a = fields.get("assignee") or None
    if a and a.get("accountId"):
        return {"id": a["accountId"], "name": a.get("displayName") or UNASSIGNED}
    if a and a.get("displayName"):
        return {"id": "", "name": a["displayName"]}
    return None


def _reporter(fields) -> dict | None:
    """The person who raised the request — the approver at the final gate."""
    r = fields.get("reporter") or {}
    if r.get("accountId"):
        return {"id": r["accountId"], "name": r.get("displayName") or UNASSIGNED}
    if r.get("displayName"):
        return {"id": "", "name": r["displayName"]}
    return None


def assignee_name(issue) -> str:
    a = _assignee(issue.get("fields") or {})
    return a["name"] if a else UNASSIGNED


# ── the main resolver ───────────────────────────────────────────────────────
def resolve_accountable(issue, status_map=None) -> dict:
    """Who is on the hook for this issue right now?

    Returns:
      owner        display name that should carry the count
      owner_id     accountId (may be "")
      role         assignee | level1 | level2 | approver
      role_label   human label for the role
      level        1 | 2 | None — the pending approval level
      co_owners    [names] — other reviewers at the same level (not counted)
      in_review    bool — the ball is with a reviewer, not the assignee
      unresolved   bool — in review but no reviewer is configured in Jira
    """
    fields   = issue.get("fields") or {}
    assignee = _assignee(fields)
    a_name   = assignee["name"] if assignee else UNASSIGNED
    a_id     = assignee["id"] if assignee else ""

    base = {
        "assignee": a_name,
        "assignee_id": a_id,
        "owner": a_name,
        "owner_id": a_id,
        "role": ROLE_ASSIGNEE,
        "role_label": ROLE_LABELS[ROLE_ASSIGNEE],
        "level": None,
        "co_owners": [],
        "in_review": False,
        "unresolved": False,
    }

    if not is_review_status(issue, status_map):
        return base

    name = status_norm(issue)
    m = LEVEL_RE.search(name)
    status_level = int(m.group(1)) if m else None

    people, level = [], status_level

    # 1) A pending approval is the most precise signal — it names both the level
    #    and the person who still owes the decision.
    pending = _pending_approvals(fields)
    if pending:
        match = next((p for p in pending if p[0] == status_level), None) if status_level else None
        level, people = match if match else pending[0]

    # 2) Otherwise use the level implied by the status name.
    if not people and status_level in LEVEL_FIELDS:
        people = _users(fields, LEVEL_FIELDS[status_level])
        level  = status_level

    # 3) "Waiting For Approval" carries no level and no Approvals record, and by
    #    the time a task reaches it the level reviewers are already done — the
    #    observed transition chain is
    #        In Progress → Revision Level 1 → Review Complete → Waiting For Approval
    #    with the last hop made by a Jira automation, not a person. What is left
    #    is the REPORTER accepting the work they asked for. Attributing this
    #    stage to a reviewer credits someone who has already signed off; to the
    #    assignee, someone who handed off two stages ago.
    if not people and status_level is None:
        rep = _reporter(fields)
        if rep:
            return {**base, "owner": rep["name"], "owner_id": rep["id"],
                    "role": ROLE_REPORTER, "role_label": ROLE_LABELS[ROLE_REPORTER],
                    "level": None, "co_owners": [], "in_review": True,
                    "unresolved": False}

    # There is still deliberately no "borrow the other level" fallback for a
    # LEVELLED status: a "Revision Level 1" with an empty Level 1 field must NOT
    # borrow the Level 2 reviewer. That reports a real person under the wrong
    # label. It reads as unresolved instead.
    if not people:
        if status_level is None:
            # Awaiting approval and no reviewer configured anywhere — the
            # assignee still owns it. Not "in review": nobody has been asked.
            return base
        # In review, but Jira has no reviewer configured. Keep the assignee so
        # the task is never orphaned, and flag it — an unrouted review is a real
        # governance gap worth showing, not hiding.
        base.update({"in_review": True, "unresolved": True, "level": status_level,
                     "role": ROLE_LEVEL2 if status_level == 2 else
                             (ROLE_LEVEL1 if status_level == 1 else ROLE_APPROVER)})
        base["role_label"] = ROLE_LABELS[base["role"]]
        return base

    role = (ROLE_LEVEL1 if level == 1 else
            ROLE_LEVEL2 if level == 2 else ROLE_APPROVER)
    primary = people[0]
    base.update({
        "owner": primary["name"],
        "owner_id": primary["id"],
        "role": role,
        "role_label": ROLE_LABELS[role],
        "level": level,
        "co_owners": [p["name"] for p in people[1:]],
        "in_review": True,
        "unresolved": False,
    })
    return base


def owner_for_mode(acc: dict, mode: str) -> str:
    """The person a given attribution mode counts an issue against.

    Returns None when the mode excludes the issue entirely (reviewer mode only
    looks at work that is actually sitting in review).
    """
    if mode == MODE_ASSIGNEE:
        return acc["assignee"]
    if mode == MODE_REVIEWER:
        return acc["owner"] if acc["in_review"] else None
    return acc["owner"]        # MODE_ACCOUNTABLE (default)
