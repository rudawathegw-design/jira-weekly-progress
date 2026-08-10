"""
calculate.py
Produces per-person stats matching the Excel layout:
  Owner | Total | Open | In Progress | Waiting For Approval | Overdue | Completed | %

"Overdue" = not-Done + past due date (cross-cutting; overlaps with Open/IP/WFA).
"Available" status is treated as Completed.
"""

import os
import sys
import json
from datetime import datetime, timezone, timedelta

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


def get_excel_category(issue) -> str:
    """Map any Jira status → one of: Open | In Progress | Waiting For Approval | Completed"""
    if is_done(issue):
        return "Completed"
    name = get_status_name(issue).lower()
    if "progress" in name:
        return "In Progress"
    if "wait" in name or "approv" in name:
        return "Waiting For Approval"
    return "Open"


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


def issue_link_record(issue) -> dict:
    f = issue.get("fields", {}) or {}
    events = _extract_events(issue)
    # Use the most recent status-change timestamp from the changelog so the
    # ticker catches every transition, not just category changes.
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
        arr = field_val if isinstance(field_val, list) else [field_val]
        for u in arr:
            if isinstance(u, dict):
                n = u.get("displayName") or u.get("name") or ""
                if n:
                    return n
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

    # Direct reviewer fields: customfield_10784 = Level 1, customfield_10785 = Level 2
    # These may be a single user object OR a list, so _first_display_name handles both.
    rev1_direct = _first_display_name(f.get("customfield_10784"))
    rev2_direct = _first_display_name(f.get("customfield_10785"))

    # Fallback: read names from the Service Desk approval workflow stages
    # customfield_10092 has structured approval info with named stages (Revision Level 1, etc.)
    approval_stages = f.get("customfield_10092") or []
    if isinstance(approval_stages, list):
        for stage in approval_stages:
            stage_name = (stage.get("name") or "").lower()
            for approver_entry in stage.get("approvers", []):
                user = approver_entry.get("approver") or {}
                n = user.get("displayName") or user.get("name") or ""
                if not n:
                    continue
                if "level 2" in stage_name and not rev2_direct:
                    rev2_direct = n
                elif "level 1" in stage_name and not rev1_direct:
                    rev1_direct = n

    return {
        "key":         issue.get("key", ""),
        "summary":     (f.get("summary") or "")[:200],
        "status":      get_status_name(issue),
        "status_from": status_from,
        "category":    get_excel_category(issue),
        "due":         f.get("duedate"),
        "overdue":     is_overdue(issue),
        "changed":     changed,
        "events":      events,
        # Issue type ("Sub-task" | "Task" | "Story" | "Epic" | …) and whether
        # it's a sub-task — powers the per-type filter in the Comment modal.
        "type":        issuetype.get("name") or "",
        "is_subtask":  bool(issuetype.get("subtask")),
        # Assignee accountId → real Jira @owner mention when posting comments.
        "assignee_id": assignee.get("accountId") or "",
        # Assignee email IF Jira exposes it (most users hide it → empty). Powers
        # the Team Directory; blanks are filled manually there.
        "assignee_email": assignee.get("emailAddress") or "",
        # Reviewer names for status-aware display in Excel exports.
        # customfield_10784 = Level 1 Reviewer, customfield_10785 = Level 2 Reviewer
        # Falls back to approval stage participants when the direct fields are empty.
        "rev1_name": rev1_direct,
        "rev2_name": rev2_direct,
    }


# ── main aggregation ───────────────────────────────────────────────────────
def compute_rates(issues, hidden_people=None):
    """Aggregate issues per assignee. ALL people are returned so the client
    can toggle hide/unhide freely; team totals are computed from the
    NON-hidden subset only so AI + headline stats exclude them."""
    hidden = set(hidden_people or [])
    counts = {}
    for issue in issues:
        name = assignee_name(issue)
        cat  = get_excel_category(issue)
        sname = get_status_name(issue)
        over  = is_overdue(issue)

        if name not in counts:
            counts[name] = {
                "total": 0, "completed": 0, "open": 0,
                "in_progress": 0, "waiting_for_approval": 0,
                "overdue": 0, "statuses": {}, "issues": [],
            }
        counts[name]["issues"].append(issue_link_record(issue))
        counts[name]["total"] += 1
        if   cat == "Completed":           counts[name]["completed"] += 1
        elif cat == "In Progress":         counts[name]["in_progress"] += 1
        elif cat == "Waiting For Approval": counts[name]["waiting_for_approval"] += 1
        else:                              counts[name]["open"] += 1
        if over:
            counts[name]["overdue"] += 1
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


# ── report builder ─────────────────────────────────────────────────────────
def build_report(issues, save_history=True, hidden_people=None):
    people, team_pct, grand_total, grand_done = compute_rates(issues, hidden_people)
    history = load_history()

    now_utc = datetime.now(timezone.utc)
    today   = now_utc.strftime("%Y-%m-%d")

    last_snap    = _find_baseline(history, today)
    last_people  = last_snap["people"] if last_snap else {}
    # Recompute baseline team_total from the baseline's people excluding
    # currently-hidden members. The stored snap["team_total"] is frozen with
    # whatever hidden list was active at SAVE time, which makes the delta
    # against today's (current-hidden-list) value misleading.
    last_team = None
    if last_snap:
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
    }

    # ── History saving ──────────────────────────────────────────────
    # Every day when SAVE_HISTORY=true, we save a snapshot.
    # Wednesdays get tagged is_weekly=true so they're the canonical baseline.
    # If today's date already in history, REPLACE it (no duplicates per day).
    if save_history:
        snapshot = {
            "date":       today,
            "timestamp":  now_utc.isoformat(timespec="seconds"),
            "team_total": team_pct,
            "is_weekly":  mark_weekly,
            "people": {
                n: {
                    "pct":   people[n]["pct"],
                    "done":  people[n]["completed"],
                    "total": people[n]["total"],
                    "open":  people[n]["open"],
                    "in_progress":         people[n]["in_progress"],
                    "waiting_for_approval": people[n]["waiting_for_approval"],
                    "overdue":   people[n]["overdue"],
                    "completed": people[n]["completed"],
                    "statuses":  people[n]["statuses"],
                }
                for n in people
            },
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
