"""
main.py
Orchestrates: fetch → calculate → analyze → build site.

SAVE_HISTORY=true  → weekly scheduled run (persists snapshot)
SAVE_HISTORY=false → manual refresh (no history saved)
"""

import os
import json
import sys
from fetch_jira   import main as fetch_main
from calculate    import build_report
from analyze      import analyze
from build_site   import build
from render_image import render as render_png


_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


def _migrate_stores_to_encrypted():
    """Idempotent: re-write any legacy plaintext PII stores as encrypted .enc
    files and drop the plaintext. Runs every build (incl. non-save cron runs)
    so a plaintext file never lingers public. schedule.json is intentionally
    NOT encrypted — it holds no PII and is read by the lightweight decide job."""
    from crypto_store import load_store, save_store
    for name in ("history.json", "hidden_people.json", "email_recipients.json"):
        plain = os.path.join(_DATA_DIR, name)
        if not os.path.exists(plain):
            continue
        try:
            save_store(plain, load_store(plain, default=[]))
            print(f"Migrated data/{name} → encrypted data/{name}.enc")
        except Exception as e:
            print(f"Encryption migration skipped for {name} (non-fatal): {e}",
                  file=sys.stderr)


def _load_hidden_people():
    from crypto_store import load_store
    try:
        data = load_store(os.path.join(_DATA_DIR, "hidden_people.json"), default=[])
        return data if isinstance(data, list) else []
    except Exception as e:
        print(f"Could not load hidden_people (non-fatal): {e}", file=sys.stderr)
        return []


def run():
    save = os.environ.get("SAVE_HISTORY", "true").strip().lower() == "true"
    # DeepSeek is only spent when an email is actually going out. All other
    # runs (cron refreshes, ad-hoc rebuilds) skip the API call.
    will_email = os.environ.get("SEND_EMAIL", "false").strip().lower() == "true"
    print(f"Save history: {save}  ·  Will send email: {will_email}")
    _migrate_stores_to_encrypted()
    hidden = _load_hidden_people()
    if hidden:
        print(f"Excluding {len(hidden)} hidden member(s) from calculation: {hidden}")
    issues   = fetch_main()
    report   = build_report(issues, save_history=save, hidden_people=hidden)
    print(f"Team completion: {report['team_total']}%  (delta: {report['team_delta']})")

    if will_email:
        analysis = analyze(report)
        print(f"AI analysis: {analysis['summary'][:80]}…")
    else:
        analysis = {"summary": "", "risks": []}
        print("AI analysis skipped — not an email run (saves DeepSeek tokens).")

    build(report, analysis, hidden_people=hidden)
    try:
        render_png(report, analysis)
    except Exception as e:
        print(f"PNG render failed (non-fatal): {e}", file=sys.stderr)
    _write_email_body(report, analysis, hidden)
    print("Done.")


def _write_email_body(report, analysis, hidden):
    """Write a polished PMO-grade HTML email body. Path: docs/email_body.html"""
    from html import escape
    docs = os.path.join(os.path.dirname(__file__), "..", "docs")
    os.makedirs(docs, exist_ok=True)

    summary  = escape(analysis.get("summary", "")).strip()
    risks    = [r for r in analysis.get("risks", []) if isinstance(r, dict) and r.get("name")][:3]
    pct      = report.get("team_total", 0)
    pct_prev = report.get("team_last_week")
    delta    = report.get("team_delta")
    done     = report.get("grand_done", 0)
    total    = report.get("grand_total", 0)
    rows     = report.get("rows", [])
    members  = len(rows)

    # ── PMO-standard derived KPIs ─────────────────────────────────────────
    overdue_count = sum(r.get("overdue", 0) for r in rows)
    in_progress   = sum(r.get("in_progress", 0) for r in rows)
    open_count    = sum(r.get("open", 0) for r in rows)
    wfa_count     = sum(r.get("waiting_for_approval", 0) for r in rows)
    not_done      = total - done
    # Schedule Performance Index proxy = 1 - overdue/not_done. Closer to 1 = on track.
    spi = round(1 - (overdue_count / not_done), 2) if not_done > 0 else 1.0
    # At-risk share = overdue / not_done (% of open work past due)
    at_risk_pct = round(100.0 * overdue_count / not_done, 1) if not_done > 0 else 0.0

    # Status colour for headline pct
    if pct >= 85:   head_col, head_bg, head_label = "#047857", "#ecfdf5", "ON TRACK"
    elif pct >= 70: head_col, head_bg, head_label = "#b45309", "#fffbeb", "AT WATCH"
    else:           head_col, head_bg, head_label = "#b91c1c", "#fef2f2", "BEHIND"

    # Delta chip — bigger, with duration ("vs N days ago")
    baseline_date = report.get("last_snap_date")
    duration_txt = ""
    if baseline_date:
        try:
            from datetime import datetime as _dt
            d1 = _dt.strptime(report["date"], "%Y-%m-%d")
            d0 = _dt.strptime(baseline_date,  "%Y-%m-%d")
            days = max(0, (d1 - d0).days)
            duration_txt = (
                "today" if days == 0 else
                "vs yesterday" if days == 1 else
                f"vs {days} days ago"
            )
        except Exception:
            duration_txt = "vs last period"
    else:
        duration_txt = "no prior period"

    if delta is None:
        d_bg, d_fg, d_arrow, d_pct = "#f1f5f9", "#475569", "", "Baseline"
    elif delta > 0:
        d_bg, d_fg, d_arrow, d_pct = "#dcfce7", "#047857", "&#9650;", f"+{delta}%"
    elif delta < 0:
        d_bg, d_fg, d_arrow, d_pct = "#fee2e2", "#b91c1c", "&#9660;", f"{delta}%"
    else:
        d_bg, d_fg, d_arrow, d_pct = "#f1f5f9", "#475569", "", "0.0%"

    # SPI chip colour
    if spi >= 0.90:   spi_col = "#047857"
    elif spi >= 0.70: spi_col = "#b45309"
    else:             spi_col = "#b91c1c"

    risks_html = "".join(
        f'''<tr><td style="padding:10px 14px;border-left:3px solid #b91c1c;
            background:#fef2f2;border-radius:0 6px 6px 0">
              <div style="font-weight:700;color:#7f1d1d;font-size:13px">{escape(r.get("name",""))}</div>
              <div style="color:#7f1d1d;font-size:12.5px;margin-top:2px">{escape(r.get("note",""))}</div>
        </td></tr><tr><td style="height:6px"></td></tr>'''
        for r in risks
    ) if risks else ""

    hidden_note = (
        f'<p style="font-size:11px;color:#94a3b8;margin:12px 0 0 0">'
        f'Excluded from metrics: {escape(", ".join(hidden))}.</p>'
        if hidden else ""
    )

    prev_row = (
        f'<tr><td style="padding:8px 0;color:#64748b;font-size:12px;border-top:1px solid #e2e8f0">Previous baseline</td>'
        f'<td style="padding:8px 0;color:#0f172a;font-size:13px;text-align:right;border-top:1px solid #e2e8f0">{pct_prev}%</td></tr>'
        if pct_prev is not None else ''
    )

    summary_block = (
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:18px">'
        f'<tr><td style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 16px">'
        f'<div style="font-size:10.5px;font-weight:700;letter-spacing:.12em;color:#2563eb;text-transform:uppercase;margin-bottom:6px">Executive summary</div>'
        f'<p style="margin:0;color:#1e293b;font-size:13.5px;line-height:1.6">{summary}</p>'
        f'</td></tr></table>'
    ) if summary else ''

    risks_block = (
        f'<div style="font-size:10.5px;font-weight:700;letter-spacing:.12em;color:#b91c1c;text-transform:uppercase;margin:0 0 8px 0">Top risks</div>'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:18px">{risks_html}</table>'
    ) if risks_html else ''

    html_body = f"""<div style="font-family:-apple-system,Segoe UI,Arial,Helvetica,sans-serif;max-width:680px;margin:0 auto;color:#0f172a;font-size:14px;line-height:1.5;background:#ffffff">

  <!-- HEADER -->
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:18px">
    <tr><td style="padding-bottom:10px;border-bottom:3px solid #0f172a">
      <div style="font-size:20px;font-weight:800;color:#0f172a;letter-spacing:-.01em">FIBTMP Progress Report</div>
      <div style="font-size:12px;color:#64748b;margin-top:3px">
        {escape(report['date'])} &nbsp;·&nbsp; Project Management Office
      </div>
    </td></tr>
  </table>

  <!-- HERO: headline %, status pill, big delta pill with duration -->
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:18px">
    <tr><td style="background:{head_bg};border:1px solid {head_col}33;border-radius:14px;padding:22px 24px">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
        <tr>
          <td style="vertical-align:middle">
            <div style="font-size:11px;font-weight:700;letter-spacing:.12em;color:{head_col};text-transform:uppercase">Team completion</div>
            <div style="font-size:52px;font-weight:800;color:{head_col};letter-spacing:-.03em;line-height:1;margin-top:4px">{pct}%</div>
            <div style="margin-top:8px;font-size:12px;font-weight:700;color:{head_col};letter-spacing:.08em">{head_label}</div>
          </td>
          <td style="vertical-align:middle;text-align:right;width:1%;white-space:nowrap">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="background:{d_bg};border:1px solid {d_fg}33;border-radius:14px">
              <tr><td style="padding:14px 20px;text-align:center">
                <div style="font-size:11px;font-weight:700;letter-spacing:.12em;color:{d_fg};text-transform:uppercase">Change</div>
                <div style="font-size:30px;font-weight:800;color:{d_fg};line-height:1;margin-top:4px;font-family:Menlo,Consolas,'JetBrains Mono',monospace">{d_arrow} {d_pct}</div>
                <div style="font-size:11px;color:{d_fg};opacity:.85;margin-top:4px;font-weight:600">{duration_txt}</div>
              </td></tr>
            </table>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>

  <!-- KPI ROW: 4 cards (PMO-standard) -->
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:18px">
    <tr>
      <td width="25%" style="padding-right:6px;vertical-align:top">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
          <tr><td style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:12px 14px">
            <div style="font-size:10px;font-weight:700;color:#94a3b8;letter-spacing:.12em">DONE</div>
            <div style="font-size:22px;font-weight:800;color:#0f172a;margin-top:4px;line-height:1">{done}<span style="color:#94a3b8;font-size:13px;font-weight:600"> / {total}</span></div>
            <div style="font-size:10.5px;color:#64748b;margin-top:3px">tasks completed</div>
          </td></tr>
        </table>
      </td>
      <td width="25%" style="padding:0 3px;vertical-align:top">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
          <tr><td style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:12px 14px">
            <div style="font-size:10px;font-weight:700;color:#94a3b8;letter-spacing:.12em">WIP</div>
            <div style="font-size:22px;font-weight:800;color:#1d4ed8;margin-top:4px;line-height:1">{in_progress}</div>
            <div style="font-size:10.5px;color:#64748b;margin-top:3px">in progress</div>
          </td></tr>
        </table>
      </td>
      <td width="25%" style="padding:0 3px;vertical-align:top">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
          <tr><td style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:12px 14px">
            <div style="font-size:10px;font-weight:700;color:#94a3b8;letter-spacing:.12em">OVERDUE</div>
            <div style="font-size:22px;font-weight:800;color:#b91c1c;margin-top:4px;line-height:1">{overdue_count}</div>
            <div style="font-size:10.5px;color:#64748b;margin-top:3px">{at_risk_pct}% of open</div>
          </td></tr>
        </table>
      </td>
      <td width="25%" style="padding-left:6px;vertical-align:top">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
          <tr><td style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:12px 14px">
            <div style="font-size:10px;font-weight:700;color:#94a3b8;letter-spacing:.12em">SPI</div>
            <div style="font-size:22px;font-weight:800;color:{spi_col};margin-top:4px;line-height:1">{spi}</div>
            <div style="font-size:10.5px;color:#64748b;margin-top:3px">schedule health</div>
          </td></tr>
        </table>
      </td>
    </tr>
  </table>

  <!-- BREAKDOWN TABLE -->
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:18px;border:1px solid #e2e8f0;border-radius:10px;overflow:hidden">
    <tr><td style="background:#f8fafc;padding:8px 14px;font-size:10.5px;font-weight:700;letter-spacing:.12em;color:#475569;text-transform:uppercase;border-bottom:1px solid #e2e8f0">Workload breakdown</td></tr>
    <tr><td style="padding:0 14px">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="font-size:13px">
        <tr><td style="padding:8px 0;color:#64748b">Open</td>            <td style="padding:8px 0;color:#0f172a;text-align:right;font-weight:600">{open_count}</td></tr>
        <tr><td style="padding:8px 0;color:#64748b;border-top:1px solid #e2e8f0">In progress</td>     <td style="padding:8px 0;color:#0f172a;text-align:right;font-weight:600;border-top:1px solid #e2e8f0">{in_progress}</td></tr>
        <tr><td style="padding:8px 0;color:#64748b;border-top:1px solid #e2e8f0">Waiting for approval</td><td style="padding:8px 0;color:#0f172a;text-align:right;font-weight:600;border-top:1px solid #e2e8f0">{wfa_count}</td></tr>
        <tr><td style="padding:8px 0;color:#64748b;border-top:1px solid #e2e8f0">Completed</td>       <td style="padding:8px 0;color:#0f172a;text-align:right;font-weight:600;border-top:1px solid #e2e8f0">{done}</td></tr>
        <tr><td style="padding:8px 0;color:#64748b;border-top:1px solid #e2e8f0">Members</td>         <td style="padding:8px 0;color:#0f172a;text-align:right;font-weight:600;border-top:1px solid #e2e8f0">{members}</td></tr>
        {prev_row}
      </table>
    </td></tr>
  </table>

  {summary_block}

  {risks_block}

  <!-- CTA -->
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:6px 0 6px 0">
    <tr><td style="background:#0f172a;border-radius:8px">
      <a href="https://rudawathegw-design.github.io/jira-weekly-progress/"
         style="display:inline-block;padding:12px 22px;color:#ffffff;
                text-decoration:none;font-weight:700;font-size:13px;letter-spacing:.02em">
        Open live dashboard &rarr;
      </a>
    </td></tr>
  </table>

  {hidden_note}

  <p style="color:#94a3b8;font-size:11px;border-top:1px solid #e2e8f0;padding-top:10px;margin-top:22px">
    PMO Team · FIBTMP. Metrics: completion %, week-over-week delta, WIP,
    overdue (% of open), SPI (1 &minus; overdue / not-done).
  </p>
</div>"""
    with open(os.path.join(docs, "email_body.html"), "w", encoding="utf-8") as f:
        f.write(html_body)


if __name__ == "__main__":
    try:
        run()
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(1)
