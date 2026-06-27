"""
analyze.py
Calls DeepSeek for a structured team analysis + individual risk flags.
Returns a dict: {"summary": str, "risks": [{"name": str, "note": str, "tip": str}]}
"""

import os
import json
import requests

DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"


def _delta_str(report):
    if report['team_delta'] is None:
        return "no prior data"
    return f"{report['team_delta']:+}%"


def build_prompt(report) -> str:
    lines = []
    for r in report["rows"]:
        if r.get("hidden"):        # skip hidden people from AI analysis
            continue
        lw  = "n/a" if r["last_week"] is None else f"{r['last_week']}%"
        dl  = "new"  if r["delta"]    is None else f"{r['delta']:+}%"
        ov  = r.get("overdue", 0)
        lines.append(
            f"  {r['owner']}: {r['this_week']}% done ({r['completed']}/{r['total']} tasks), "
            f"open={r['open']}, in-progress={r['in_progress']}, "
            f"waiting-approval={r['waiting_for_approval']}, overdue={ov}, "
            f"last-week={lw}, change={dl}"
        )
    table = "\n".join(lines)

    return (
        "You are a senior PMO consultant reviewing weekly Jira progress for a major bank "
        "transformation programme. Be specific, name people, quantify everything, and "
        "give actionable advice a steering committee can act on this week.\n\n"
        "WRITING STYLE — strict rules:\n"
        "  - Plain, neutral, executive tone. No dramatic language.\n"
        "  - BANNED phrases (do not use, paraphrase, or imply): 'workload imbalance is stark', "
        "    'severely', 'severely dragging', 'critically', 'urgent', 'crisis', 'alarming', "
        "    'concerning', 'red flag', 'bottleneck', 'overload', 'overloaded', 'stalled', "
        "    'unblock progress', 'stark', 'major concern', 'significant concern'.\n"
        "  - Do NOT moralise or recommend punitive action. Describe what the data shows.\n"
        "  - State workload distribution as numbers (e.g. 'falah holds 104 of 410 tasks; "
        "    other members hold 1-30'). Do not call it 'imbalance' or 'stark'.\n"
        "  - One short sentence per idea. Avoid back-to-back adjectives.\n\n"
        f"Date: {report['date']}\n"
        f"Team completion: {report['team_total']}% ({_delta_str(report)} vs last week)\n"
        f"Total tasks: {report.get('grand_total', '?')} | Done: {report.get('grand_done', '?')}\n\n"
        f"Per-member breakdown:\n{table}\n\n"
        "Respond in JSON with EXACTLY this schema (no extra keys):\n"
        "{\n"
        '  "summary": "4-6 sentence narrative covering: (1) overall team trend and headline number, '
        '(2) top 2 performers with their numbers, (3) top 2-3 concerns with specifics, '
        '(4) capacity/workload imbalance observations, (5) one strategic recommendation for the steering committee",\n'
        '  "risks": [\n'
        '    {\n'
        '      "name": "exact owner name from the table",\n'
        '      "note": "2-sentence diagnosis: what is wrong AND why it matters to the programme",\n'
        '      "tip": "specific action with owner/timeline: e.g. \\"Re-distribute 3 of falah\'s open tasks to ahmad and Idris by Friday\\""\n'
        '    }\n'
        "  ]\n"
        "}\n\n"
        "Risk inclusion criteria (be aggressive — bank transformation needs early warning):\n"
        "  - Anyone with completion < 70%\n"
        "  - Anyone with overdue > 0\n"
        "  - Anyone with negative weekly delta\n"
        "  - Anyone stuck at 0% with > 1 task\n"
        "  - Anyone with In Progress > 8 (WIP overload)\n"
        "Rank risks by severity (worst first). Cap at 8 risks max. "
        "If everyone is genuinely on track, return risks as an empty array. "
        "Use plain English. No markdown inside strings. No emoji. "
        "Names must match the breakdown table EXACTLY (including capitalisation)."
    )


def analyze(report) -> dict:
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        return {
            "summary": "AI analysis skipped — DEEPSEEK_API_KEY is not set. "
                       "Add it as a GitHub Secret to enable commentary.",
            "risks": [],
        }

    payload = {
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": build_prompt(report)}],
        "response_format": {"type": "json_object"},
        "temperature": 0.3,
        "max_tokens": 2500,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(DEEPSEEK_URL, headers=headers,
                             data=json.dumps(payload), timeout=90)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"].strip()
        # Robust parse: if JSON got truncated, try to repair
        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            # Truncated — find last valid risk object and close array+object
            # Strip everything after last complete }] or last complete }
            repaired = content
            for cut in range(len(content), 0, -1):
                try:
                    result = json.loads(repaired[:cut] + ("]}" if '"risks"' in repaired[:cut] else "}"))
                    break
                except json.JSONDecodeError:
                    continue
            else:
                # Last resort: extract summary substring
                idx = content.find('"summary"')
                if idx >= 0:
                    end = content.find('",', idx + 11)
                    summary = content[idx+11:end] if end > 0 else "Analysis truncated."
                    return {"summary": summary, "risks": []}
                return {"summary": "AI returned malformed JSON.", "risks": []}
        return {
            "summary": result.get("summary", ""),
            "risks":   [r for r in result.get("risks", []) if isinstance(r, dict) and r.get("name")],
        }
    except Exception as e:
        return {"summary": f"AI analysis unavailable this period ({type(e).__name__}: {e}).", "risks": []}
