"""
calculate.py
Produces per-person stats matching the Excel layout:
  Owner | Total | Open | In Progress | Waiting For Approval | Overdue | Completed | %

"Overdue" = not-Done + past due date (cross-cutting; overlaps with Open/IP/WFA).
"Available" status is treated as Completed.

Attribution: an issue at "Revision Level 1/2" is counted against that level's
reviewer, not the assignee — see accountability.py. The dashboard can re-group
client-side into any mode, so this module bakes BOTH series into every history
snapshot (`people` = assignee mode, `people_acc` = accountable mode) and picks
the matching one when computing week-over-week deltas.
"""

import os
import sys
import json
from datetime import datetime, timezone, timedelta

from accountability import (
    resolve_accountable, owner_for_mode, bucket_for,
    DEFAULT_STATUS_BUCKETS,
    MODE_ASSIGNEE, MODE_ACCOUNTABLE, MODE_REVIEWER,
    BUCKET_COMPLETED, BUCKET_PROGRESS, BUCKET_WFA,
)

HISTORY_PATH  = os.path.join(os.path.dirname(__file__), "..", "data", "history.json")
SCHEDULE_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "schedule.json")


def _weekly_python_weekday(default_py=2):
    """Return the configured weekly-baseline day as a Python weekday
    (Mon=0 … Sun=6). The admin UI stores `weekly_day` in cron/JS convention
    (Sun=0 … Sat=6) in data/schedule.json, so convert. Default = Wednesday.
    The env var WEEKLY_DAY (Python convention) overrides the file if set."""
    env = os.environ.get("WEEKLY_DAY", "").strip()
    if env.isdigit():
        return int(env) % 7
    try:
        with open(SCHEDULE_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
        wd = cfg.get("weekly_day")
        if wd is not None:
            # Sun=0..Sat=6  →  Mon=0..Sun=6
            return (int(wd) + 6) % 7
    except (OSError, ValueError, KeyError):
        pass
    return default_py


# ── status helpers ─────────────────────────────────────────────────────────
def is_done(issue) -> bool:
    fields   = issue.get("fields", {})
    status   = fields.get("status") or {}
    name     = (status.get("name") or "").strip().lower()
    if name == "available":
        return True
    category = status.get("statusCategory") or {}
    return category.get("key") == "done"


def get_status_name(issue) -> str:
    return (issue.get("fields", {}).get("status") or {}).get("name") or "Unknown"


def get_excel_category(issue, status_map=None) -> str:
    """Map any Jira status → one of: Open | In Progress | Waiting For Approval | Completed

    NOTE: "Revision Level 1"/"Revision Level 2" now land in Waiting For Approval.
    The previous rule tested only "wait"/"approv", which matches neither, so
    every task parked in review fell through to Open and overstated it.
    The dashboard exposes this mapping in a Status Mapping panel.
    """
    return bucket_for(issue, status_map)


def is_overdue(issue) -> bool:
    """True if the issue is NOT done AND its due date is in the past."""
    if is_done(issue):
        return False
    due = (issue.get("fields", {}) or {}).get("duedate")
    if not due:
        return False
    try:
        due_dt = datetime.strptime(str(due)[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > due_dt
    except (ValueError, TypeError):
        return False


def assignee_name(issue) -> str:
    a = (issue.get("fields", {}) or {}).get("assignee")
    if a and a.get("displayName"):
        return a["displayName"]
    return "Unassigned"


def _extract_events(issue, max_age_days: int = 30) -> list:
    """Pull (author, field, from, to, when) for status / duedate / assignee
    changes from the issue's changelog, keeping only entries newer than
    max_age_days. Returns list sorted newest-first."""
    cl = (issue.get("changelog") or {}).get("histories") or []
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    interesting = {"status", "duedate", "assignee", "priority"}
    out = []
    for h in cl:
        when = h.get("created")
        if not when:
            continue
        try:
            when_dt = datetime.strptime(when[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
        if when_dt < cutoff:
            continue
        author = (h.get("author") or {}).get("displayName") or "Unknown"
        for it in h.get("items") or []:
            field = (it.get("field") or "").lower()
            if field not in interesting:
                continue
            out.append({
                "when":   when,
                "author": author,
                "field":  field,
                "from":   it.get("fromString") or "",
                "to":     it.get("toString") or "",
            })
    out.sort(key=lambda e: e["when"], reverse=True)
    return out[:20]   # cap per issue


def issue_link_record(issue, status_map=None) -> dict:
    f = issue.get("fields", {}) or {}
    events = _extract_events(issue)
    acc = resolve_accountable(issue, status_map)
    last_status_event = next((e for e in events if e["field"] == "status"), None)
    changed = (last_status_event["when"] if last_status_event
               else f.get("statuscategorychangedate") or f.get("updated"))
    status_from = last_status_event["from"] if last_status_event else None
    assignee = f.get("assignee") or {}
    issuetype = f.get("issuetype") or {}

    def _first_display_name(field_val):
        """Extract the first displayName from a Jira user custom field (array or single obj)."""
        if not field_val:
            return ""
        
        # If it's a list, take the first item
        if isinstance(field_val, list):
            if not field_val:
                return ""
            field_val = field_val[0]
        
        # If it's a dict with displayName
        if isinstance(field_val, dict):
            return field_val.get("displayName") or field_val.get("name") or ""
        
        # If it's a string, return it
        if isinstance(field_val, str):
            return field_val
        
        return ""

    def _first_approver_from_stages(approval_stages):
        """Extract the first approver displayName from customfield_10092 approval stages."""
        if not isinstance(approval_stages, list):
            return ""
        for stage in approval_stages:
            for approver_entry in stage.get("approvers", []):
                user = approver_entry.get("approver") or {}
                n = user.get("displayName") or user.get("name") or ""
                if n:
                    return n
        return ""

    # ✅ DIRECT REVIEWER FIELDS - FIXED
    # customfield_10784 = Level 1 Reviewer
    # customfield_10785 = Level 2 Reviewer
    rev1_direct = _first_display_name(f.get("customfield_10784"))
    rev2_direct = _first_display_name(f.get("customfield_10785"))

    # Fallback: read names from the Service Desk approval workflow stages
    approval_stages = f.get("customfield_10092") or []
    if isinstance(approval_stages, list):
        for idx, stage in enumerate(approval_stages):
            stage_name = (stage.get("name") or "").lower()
            for approver_entry in stage.get("approvers", []):
                user = approver_entry.get("approver") or {}
                n = user.get("displayName") or user.get("name") or ""
                if not n:
                    continue
                # If we already have a direct reviewer, prefer that
                if "level 2" in stage_name and not rev2_direct:
                    rev2_direct = n
                elif "level 1" in stage_name and not rev1_direct:
                    rev1_direct = n
                else:
                    if idx == 0 and not rev1_direct:
                        rev1_direct = n
                    elif idx == 1 and not rev2_direct:
                        rev2_direct = n

    return {
        "key":         issue.get("key", ""),
        "summary":     (f.get("summary") or "")[:200],
        "status":      get_status_name(issue),
        "status_from": status_from,
        "category":    get_excel_category(issue, status_map),
        # Explicit done flag: the browser re-buckets issues when the admin edits
        # the Status Mapping, and done-ness comes from Jira's status CATEGORY,
        # which isn't recoverable from the status name alone.
        "done":        is_done(issue),
        "due":         f.get("duedate"),
        "overdue":     is_overdue(issue),
        "changed":     changed,
        "events":      events,
        "type":        issuetype.get("name") or "",
        "is_subtask":  bool(issuetype.get("subtask")),
        "assignee_id": assignee.get("accountId") or "",
        "assignee_email": assignee.get("emailAddress") or "",
        # ✅ REVIEWER NAMES - FIXED
        "rev1_name": rev1_direct,  # Level 1 Reviewer
        "rev2_name": rev2_direct,  # Level 2 Reviewer
        # "Involved Users" (customfield_10520) — participants, not approvers.
        # Carried through for the exports; NOT used to decide accountability.
        "involved_name": _first_display_name(f.get("customfield_10520")),
        # ── Accountability ────────────────────────────────────────────────
        # Who the task is *assigned* to vs. who must act on it *right now*.
        # Both travel with the record so the browser can re-group into any
        # attribution mode without another Jira round-trip.
        "assignee_name":   acc["assignee"],
        "accountable":     acc["owner"],
        "accountable_id":  acc["owner_id"],
        "acc_role":        acc["role"],
        "acc_role_label":  acc["role_label"],
        "pending_level":   acc["level"],
        "co_reviewers":    acc["co_owners"],
        "in_review":       acc["in_review"],
        # In review but Jira has no reviewer configured — a routing gap the
        # dashboard surfaces rather than silently blaming the assignee for.
        "reviewer_unresolved": acc["unresolved"],
    }

# ── main aggregation ───────────────────────────────────────────────────────
def compute_rates(issues, hidden_people=None, mode=MODE_ACCOUNTABLE, status_map=None):
    """Aggregate issues per person. ALL people are returned so the client
    can toggle hide/unhide freely; team totals are computed from the
    NON-hidden subset only so AI + headline stats exclude them.

    `mode` decides who each issue counts against:
      assignee     — classic; always the assignee
      accountable  — default; the reviewer while the task sits in review
      reviewer     — only in-review work, grouped by the reviewer holding it

    Each issue counts exactly ONCE (the primary reviewer carries it, with any
    co-reviewers listed but not counted), so per-person totals always sum to the
    team total and completion %% stays meaningful.
    """
    hidden = set(hidden_people or [])
    counts = {}
    for issue in issues:
        acc  = resolve_accountable(issue, status_map)
        name = owner_for_mode(acc, mode)
        if name is None:            # reviewer mode: not in review → out of scope
            continue
        cat  = get_excel_category(issue, status_map)
        sname = get_status_name(issue)
        over  = is_overdue(issue)

        if name not in counts:
            counts[name] = {
                "total": 0, "completed": 0, "open": 0,
                "in_progress": 0, "waiting_for_approval": 0,
                "overdue": 0, "statuses": {}, "issues": [],
                # Overdue split by WHY it is late: work not delivered vs. a
                # review decision not made. Same task, very different follow-up.
                "overdue_delivery": 0, "overdue_review": 0,
                "in_review": 0, "reviewer_unresolved": 0,
            }
        counts[name]["issues"].append(issue_link_record(issue, status_map))
        counts[name]["total"] += 1
        if   cat == BUCKET_COMPLETED: counts[name]["completed"] += 1
        elif cat == BUCKET_PROGRESS:  counts[name]["in_progress"] += 1
        elif cat == BUCKET_WFA:       counts[name]["waiting_for_approval"] += 1
        else:                         counts[name]["open"] += 1
        if over:
            counts[name]["overdue"] += 1
            if acc["in_review"]:
                counts[name]["overdue_review"] += 1
            else:
                counts[name]["overdue_delivery"] += 1
        if acc["in_review"]:
            counts[name]["in_review"] += 1
        if acc["unresolved"]:
            counts[name]["reviewer_unresolved"] += 1
        counts[name]["statuses"][sname] = counts[name]["statuses"].get(sname, 0) + 1

    people = {}
    grand_total = grand_done = 0      # visible-only aggregates (for stats + AI)
    for name, c in counts.items():
        pct = round(100.0 * c["completed"] / c["total"], 1) if c["total"] else 0.0
        people[name] = {
            "total": c["total"],
            "open": c["open"],
            "in_progress": c["in_progress"],
            "waiting_for_approval": c["waiting_for_approval"],
            "overdue": c["overdue"],
            "overdue_delivery": c["overdue_delivery"],
            "overdue_review": c["overdue_review"],
            "in_review": c["in_review"],
            "reviewer_unresolved": c["reviewer_unresolved"],
            "completed": c["completed"],
            "pct": pct,
            "done": c["completed"],   # legacy alias
            "statuses": c["statuses"],
            "issues": c["issues"],
            "hidden": name in hidden,  # tag so client knows
        }
        if name not in hidden:        # exclude from headline totals
            grand_total += c["total"]
            grand_done  += c["completed"]

    team_pct = round(100.0 * grand_done / grand_total, 1) if grand_total else 0.0
    return people, team_pct, grand_total, grand_done


# ── history helpers (encrypted at rest) ─────────────────────────────────────
# History holds real names + per-person numbers, so it is stored encrypted as
# data/history.json.enc (AES-GCM, key from SITE_PASSWORD). load_store falls back
# to the legacy plaintext data/history.json on the first encrypted run, so no
# snapshots are lost during migration. The browser reads history from the
# encrypted dashboard blob, not this file.
from crypto_store import load_store, save_store


def load_history():
    os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
    return load_store(HISTORY_PATH, default=[]) or []


def save_history_data(history):
    os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
    save_store(HISTORY_PATH, history)


def _parse_prev(v):
    """Normalise a history per-person value (old: float, new: dict)."""
    if v is None:
        return None
    if isinstance(v, dict):
        return v
    return {
        "pct": float(v), "done": None, "total": None,
        "open": 0, "in_progress": 0, "waiting_for_approval": 0,
        "overdue": 0, "completed": None, "statuses": {},
    }


def _pinned_baseline_date():
    """Admin-pinned baseline from data/schedule.json: a YYYY-MM-DD date,
    the string "latest" (auto-follow the newest snapshot), or None."""
    try:
        with open(SCHEDULE_PATH, encoding="utf-8") as f:
            return (json.load(f).get("pinned_baseline") or None)
    except (OSError, ValueError):
        return None


def _find_baseline(history, today_str):
    """Find baseline snapshot for week-over-week comparison.
    Priority: admin-pinned ("latest" or a specific date) > most recent prior
    snapshot on the configured weekly day > most recent prior weekly-tagged
    snapshot > most recent prior. Never returns today's own snapshot
    (except an explicit date pin, which is an admin's deliberate choice).
    """
    pinned = _pinned_baseline_date()
    if pinned:
        if str(pinned).strip().lower() == "latest":
            # Auto-advancing pin: newest snapshot strictly before today, so a
            # freshly saved snapshot never compares against itself.
            prior = [s for s in history if s.get("date", "") < today_str]
            if prior:
                return prior[-1]
        else:
            hit = next((s for s in history if s.get("date") == pinned), None)
            if hit:
                return hit
    prior = [s for s in history if s.get("date", "") < today_str]
    if not prior:
        return None
    wd = _weekly_python_weekday()
    on_day = []
    for s in prior:
        try:
            if datetime.strptime(s.get("date", "")[:10], "%Y-%m-%d").weekday() == wd:
                on_day.append(s)
        except (ValueError, TypeError):
            continue
    if on_day:
        return on_day[-1]
    weekly = [s for s in prior if s.get("is_weekly")]
    if weekly:
        return weekly[-1]
    return prior[-1]


def _snapshot_people(snap, mode):
    """Per-person numbers from a history snapshot, for the given attribution mode.

    Snapshots written from this version carry a series per mode. Older snapshots
    have only the assignee-mode `people` — for those we return None in another
    mode rather than comparing against numbers computed a different way, so a
    delta is shown as "new" instead of a confidently wrong figure.
    """
    if not snap:
        return {}
    if mode == MODE_ASSIGNEE:
        return snap.get("people") or {}
    key = "people_acc" if mode == MODE_ACCOUNTABLE else "people_rev"
    if key in snap:
        return snap.get(key) or {}
    return None          # snapshot predates dual-mode history


# ── report builder ─────────────────────────────────────────────────────────
def build_report(issues, save_history=True, hidden_people=None,
                 mode=MODE_ACCOUNTABLE, status_map=None):
    people, team_pct, grand_total, grand_done = compute_rates(
        issues, hidden_people, mode, status_map)
    history = load_history()

    now_utc = datetime.now(timezone.utc)
    today   = now_utc.strftime("%Y-%m-%d")

    last_snap    = _find_baseline(history, today)
    # Compare like with like: pull the baseline series computed under the SAME
    # attribution mode. None means the snapshot predates dual-mode history.
    last_people  = _snapshot_people(last_snap, mode)
    baseline_mode_gap = last_snap is not None and last_people is None
    if last_people is None:
        last_people = {}
    # Recompute baseline team_total from the baseline's people excluding
    # currently-hidden members. The stored snap["team_total"] is frozen with
    # whatever hidden list was active at SAVE time, which makes the delta
    # against today's (current-hidden-list) value misleading.
    last_team = None
    if last_snap and last_people:
        hidden_set = set(hidden_people or [])
        tot = done = 0
        for n, p in last_people.items():
            if n in hidden_set:
                continue
            if isinstance(p, dict):
                tot  += p.get("total", 0) or 0
                done += p.get("done") if p.get("done") is not None else (p.get("completed", 0) or 0)
        last_team = round(100.0 * done / tot, 1) if tot else None

    rows = []
    for name in sorted(people.keys(), key=str.lower):
        this = people[name]
        prev = _parse_prev(last_people.get(name))
        delta = round(this["pct"] - prev["pct"], 1) if prev is not None else None

        def lp(key, default=0):
            if prev is None: return default
            return prev.get(key, default) if isinstance(prev, dict) else default

        rows.append({
            "owner":   name,
            # This week
            "total":              this["total"],
            "open":               this["open"],
            "in_progress":        this["in_progress"],
            "waiting_for_approval": this["waiting_for_approval"],
            "overdue":            this["overdue"],
            # Why the overdue items are late: undelivered work vs. an unmade
            # review decision. Drives the split shown in the Overdue panel.
            "overdue_delivery":   this["overdue_delivery"],
            "overdue_review":     this["overdue_review"],
            "in_review":          this["in_review"],
            "reviewer_unresolved": this["reviewer_unresolved"],
            "completed":          this["completed"],
            "this_week":          this["pct"],
            # Last week (baseline = most recent prior Wednesday, fallback most recent prior)
            "last_week":          prev["pct"] if prev else None,
            "last_total":         lp("total"),
            "last_open":          lp("open"),
            "last_in_progress":   lp("in_progress"),
            "last_wfa":           lp("waiting_for_approval"),
            "last_overdue":       lp("overdue"),
            "last_completed":     lp("completed"),
            # Delta
            "delta":              delta,
            # Legacy
            "done":               this["completed"],
            "statuses":           this["statuses"],
            "issues":             this.get("issues", []),
            "hidden":             this.get("hidden", False),
            "last_statuses":      prev.get("statuses", {}) if prev else {},
        })

    team_delta = round(team_pct - last_team, 1) if last_team is not None else None
    last_snap_date = last_snap["date"] if last_snap else None
    last_snap_time = last_snap.get("timestamp") if last_snap else None
    # Configurable weekly-baseline day (admin → data/schedule.json weekly_day),
    # or forced via env var (to manually reset the baseline). Default Wednesday.
    is_weekly_day = now_utc.weekday() == _weekly_python_weekday()
    force_weekly  = os.environ.get("FORCE_WEEKLY", "").strip().lower() == "true"
    mark_weekly = is_weekly_day or force_weekly

    report = {
        "date":             today,
        "timestamp":        now_utc.isoformat(timespec="seconds"),
        "jira_base_url":    os.environ.get("JIRA_BASE_URL", "https://fibtask.atlassian.net").rstrip("/"),
        "last_snap_date":   last_snap_date,
        "last_snap_time":   last_snap_time,
        "team_total":       team_pct,
        "team_last_week":   last_team,
        "team_delta":       team_delta,
        "grand_total":      grand_total,
        "grand_done":       grand_done,
        "rows":             rows,
        "has_previous":     last_snap is not None,
        "is_today_weekly":  mark_weekly,
        "history":          history,
        # Attribution context, so the page can label what it is showing and warn
        # when a baseline cannot be compared like-for-like.
        "attribution_mode":  mode,
        "status_map":        status_map or DEFAULT_STATUS_BUCKETS,
        "baseline_mode_gap": baseline_mode_gap,
    }

    # ── History saving ──────────────────────────────────────────────
    # Every day when SAVE_HISTORY=true, we save a snapshot.
    # Wednesdays get tagged is_weekly=true so they're the canonical baseline.
    # If today's date already in history, REPLACE it (no duplicates per day).
    if save_history:
        def _series(pp):
            return {
                n: {
                    "pct":   pp[n]["pct"],
                    "done":  pp[n]["completed"],
                    "total": pp[n]["total"],
                    "open":  pp[n]["open"],
                    "in_progress":         pp[n]["in_progress"],
                    "waiting_for_approval": pp[n]["waiting_for_approval"],
                    "overdue":   pp[n]["overdue"],
                    "overdue_delivery": pp[n].get("overdue_delivery", 0),
                    "overdue_review":   pp[n].get("overdue_review", 0),
                    "in_review":        pp[n].get("in_review", 0),
                    "completed": pp[n]["completed"],
                    "statuses":  pp[n]["statuses"],
                }
                for n in pp
            }

        # Snapshot EVERY attribution mode, not just the active one. The mode is
        # a per-user client-side choice, so a snapshot written under one mode
        # must still yield an honest week-over-week delta under another. Storing
        # all three costs a little space and removes the whole class of
        # apples-to-oranges comparison bugs.
        assignee_people, assignee_team, _, _ = compute_rates(
            issues, hidden_people, MODE_ASSIGNEE, status_map)
        reviewer_people, _, _, _ = compute_rates(
            issues, hidden_people, MODE_REVIEWER, status_map)
        acc_people = (people if mode == MODE_ACCOUNTABLE else
                      compute_rates(issues, hidden_people, MODE_ACCOUNTABLE, status_map)[0])

        snapshot = {
            "date":       today,
            "timestamp":  now_utc.isoformat(timespec="seconds"),
            # team_total stays the assignee-mode figure so the existing History
            # tab and every previously saved snapshot remain on one comparable
            # scale. Mode-specific team %s are derived from the series below.
            "team_total": assignee_team,
            "is_weekly":  mark_weekly,
            "snapshot_mode": mode,
            "people":     _series(assignee_people),   # classic (assignee)
            "people_acc": _series(acc_people),        # accountable-now
            "people_rev": _series(reviewer_people),   # reviewer workload
        }
        # Remove existing entry for today (in case of multiple runs same day)
        history = [s for s in history if s.get("date") != today]
        history.append(snapshot)
        # Keep sorted by date
        history.sort(key=lambda s: s.get("date", ""))
        save_history_data(history)
        # Plaintext marker (date only, no PII) so the workflow's decide job can
        # detect a missed weekly slot and catch up later the same day.
        try:
            marker = os.path.join(os.path.dirname(HISTORY_PATH), "last_snapshot_date.txt")
            with open(marker, "w", encoding="utf-8") as f:
                f.write(today + "\n")
        except OSError as e:
            print(f"Could not write snapshot marker (non-fatal): {e}", file=sys.stderr)
        report["history"] = history

    return report
