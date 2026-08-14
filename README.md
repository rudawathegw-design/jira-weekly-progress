# Jira Weekly Progress Report

Automatically pulls issues from Jira every **Tuesday**, calculates each team
member's completion rate (% of their assigned issues that are **Done**),
compares it to the previous week, has **DeepSeek** write a short analysis, and
publishes a polished report to **GitHub Pages** â€” all free, all inside this repo.

No server, no hosting bill. GitHub Actions runs the job; GitHub Pages serves the page.

---

## How it works

```
Tuesday 06:00 UTC
   â”‚
   â–¼
GitHub Actions runs src/main.py
   â”‚
   â”œâ”€ fetch_jira.py   pulls all issues (new /rest/api/3/search/jql API)
   â”œâ”€ calculate.py    computes Done% per person + compares to last week
   â”œâ”€ analyze.py      DeepSeek writes the summary
   â””â”€ build_site.py   renders docs/index.html
   â”‚
   â–¼
Commits docs/index.html + data/history.json back to the repo
   â”‚
   â–¼
GitHub Pages publishes the new report
```

`data/history.json` is the memory: each week's numbers are saved there, so the
next run can show the week-over-week change. **Don't delete it.**

---

## One-time setup

### 1. Create the repo
Upload these files to a new GitHub repository (or push this folder).

### 2. Get a Jira API token
1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
2. Create a token and copy it.

### 3. Get a DeepSeek API key
1. Go to https://platform.deepseek.com/ , create a key, copy it.
2. (If you'd rather skip AI, leave this secret unset â€” the report still builds,
   with a note in place of the analysis.)

### 4. Add GitHub Secrets
In your repo: **Settings â†’ Secrets and variables â†’ Actions â†’ New repository secret.**
Add these five:

| Secret name        | Value (example)                       |
|--------------------|---------------------------------------|
| `JIRA_EMAIL`       | your-email@example.com                |
| `JIRA_API_TOKEN`   | (the token from step 2)               |
| `JIRA_BASE_URL`    | https://your-site.atlassian.net         |
| `JIRA_PROJECT`     | YOURPROJECT                                |
| `DEEPSEEK_API_KEY` | (the key from step 3)                 |

> Secrets are encrypted. They are never written into the code or the page.

### 5. Enable GitHub Pages
**Settings â†’ Pages â†’ Build and deployment â†’ Source: Deploy from a branch.**
Set **Branch: `main`** and **Folder: `/docs`**, then Save.
Your report will live at:
`https://<your-username>.github.io/<repo-name>/`

### 6. Run it once manually
Go to the **Actions** tab â†’ **Weekly Progress Report** â†’ **Run workflow**.
This produces the first report. (The first run has no "last week" data, so the
Change column will show blanks/NEW â€” that's expected. From the second run on,
comparisons appear.)

---

## Configuration

- **Schedule:** edit the `cron` line in `.github/workflows/weekly.yml`.
  `0 6 * * 2` = Tuesdays 06:00 UTC. Use https://crontab.guru to pick another time.
- **What counts as "Done":** any status whose category is *Done* (covers Done,
  Closed, Resolved, etc.). Defined in `src/calculate.py` â†’ `is_done()`.
- **Which issues are counted:** everyone's issues in the project. To narrow it
  (e.g. only the current sprint), edit the `jql` string in `src/fetch_jira.py`.

---

## Owner attribution (who a task counts against)

The assignee owns **delivery**. But once a task moves to **Revision Level 1/2**,
the assignee has handed off — the person who must act is that level's reviewer.
Counting such a task (especially an overdue one) against the assignee blames the
wrong person and sends the follow-up to the wrong desk.

The dashboard's **attribution bar** (top of the page, above the stats) controls this:

| Mode | Counts a task against |
|------|-----------------------|
| **Assignee** | The assignee, always (classic behaviour) |
| **Accountable Now** *(default)* | The reviewer while the task is in review; the assignee otherwise |
| **Review Queue** | Only work awaiting a review decision, grouped by the reviewer who owes it |

Alongside it: an **issue-type scope** filter (Task / Sub-task / Epic / …) and a
**Status mapping** panel that decides which reporting column each Jira status
rolls up into. All three persist in `localStorage`, so a refresh keeps your view.

### How the reviewer is resolved

`src/accountability.py` is the single source of truth (mirrored in the browser as
`_ACC` in `build_site.py`, so the live 10-second refresh can never disagree with
the built page). First hit wins:

1. A **pending** entry in the *Approvals* field (`customfield_10092`) — names both
   the level and who still owes the decision.
2. The level implied by the status name → that level's Reviewers field
   (`customfield_10784` for Level 1, `customfield_10785` for Level 2).
3. *Waiting For Approval* (no level of its own) → Level 1 Reviewers, then Level 2.
4. Otherwise the assignee, flagged **unresolved** — "in review but no reviewer
   configured in Jira" is surfaced as a governance gap rather than silently
   blamed on the assignee.

`customfield_10520` (*Involved Users*) is deliberately **not** part of this chain
— being involved in a task doesn't make you the person who owes the decision. It
still travels through to the exports as `involved_name`.

Where a level has several reviewers, the **first carries the count** and the rest
are listed as co-reviewers. Each task counts exactly once, so per-person totals
always sum to the team total.

Two consequences worth knowing:

- **Team completion % is unchanged by the mode.** Only the per-person
  distribution moves; completed work is always attributed to its assignee.
- **`Revision Level 1/2` now roll up into *Waiting For Approval*.** The old rule
  tested only `"wait"`/`"approv"`, which matches neither, so every task parked in
  review fell through to *Open* and overstated it. Change it back in the Status
  mapping panel if you prefer the old split.

History snapshots store a series **per mode**, so week-over-week deltas compare
like with like. Snapshots written before this feature only have the assignee-mode
series; in another mode the change column is hidden rather than shown wrongly.

### In the Excel export

`Export Excel` names the person actually on the hook. The **Tasks** sheet carries
`Assignee`, `Accountable Now`, `Accountable Role`, `Pending Level`,
`Co-reviewers`, `Involved Users`, and an `Overdue Reason` separating *delivery
not complete* from *awaiting review decision*. A **Review Bottlenecks** sheet
ranks reviewers by queue size, and a **Report Info** cover sheet records the
mode, scope, and status mapping the numbers were produced under.

---

## Versioning

`SITE_VERSION` in `src/build_site.py` is stamped into every build and shown:

- on the **sign-in screen**, bottom-right — deliberately outside the password
  gate, so you can confirm which build is live without logging in;
- in the **footer** once you're in;
- on the **Report Info** sheet of the Excel export.

The badge reads `v<version> · <build date> · <short commit>`. Bump the MINOR
digit for a feature, PATCH for a fix.

> **After changing `worker/github-proxy.js`, redeploy the Worker** — otherwise
> the every-10s live refresh keeps returning the old field set and the live view
> silently falls back to assignee attribution while the built page uses the new
> one. The dashboard detects this case and says so rather than reporting "no
> reviewer set in Jira" for everything:
> ```bash
> cd worker && npx wrangler deploy
> ```

---

## Commenting on overdue issues

Open the **âš  Overdue** modal on the dashboard and click **ðŸ’¬ Comment in Jira**:

- **Pick the issue types** to include (Sub-task / Task / Story / Epic / Bug â€¦) â€”
  toggle chips at the top; deselect individual issues in the list to exclude them.
- **Edit the comment body.** `@owner` becomes a real Jira mention of the issue's
  assignee; `@cc` becomes mentions of the **CC people** (comma-separated emails,
  prefilled from your saved recipients "sheet" `data/email_recipients.json`).
  The default body is `@owner, what is the update on this task?` + `CC: @cc`.
- **Preview + confirm**, then click **Post**. The dashboard commits
  `data/comment_queue.json` and triggers the **Post Jira Comments** workflow,
  which resolves the mentions server-side and posts each comment to Jira, then
  writes `data/comment_log.json` and clears the queue.

No extra secrets are needed â€” `comments.yml` reuses `JIRA_EMAIL`,
`JIRA_API_TOKEN`, and `JIRA_BASE_URL`.

---

## Exporting one epic's daily status (Excel)

The **More → Export Epic Excel** button opens a small dialog asking **which
date to start from** (defaults to `EPIC_HISTORY_START`, or whatever you
picked last time — it's remembered in your browser). Confirming downloads a
coloured `.xlsx` for epic **FIBTMP-489**: every task and subtask under it,
one row each, with columns **Key**, **Summary**, **Owner** (the task's own
assignee), **Type**, then **one status column per day** from your chosen
start date through today (side by side, so a status frozen across many days
jumps out in the row), then **Idle Days** and **Link** (a clickable Jira
link, last column). It's meant for a quick send-up to management showing
who isn't actually moving their tasks.

- **Pick the start date each time** in the "Export Epic Excel" dialog —
  no code edits needed for a different range. Your last choice is
  remembered (per browser) for next time.
- **Every day is its own column**, laid out left to right, so a manager can
  scan a row and immediately see an owner sitting on the same status for
  days at a time. Day columns wrap long status text onto 1-2 lines inside
  the cell (rather than overflowing into the next day's column), so
  something like "Revision Level 1" stays readable and doesn't bleed into
  the neighbouring day.
- **Row 1 is a "Generated" banner** merged across the whole sheet — it
  spells out the epic, the date range, and the exact date/time the file was
  pulled, so anyone opening it (or a forwarded copy) can tell at a glance
  how fresh it is, on top of the "(Today)" tag on the last day column.
- **Today's column is always live** — fetched fresh at the moment of
  download, so exporting once a day or ten times a day always shows the
  current state.
- **Idle Days** counts how many days in a row (ending today) the status
  hasn't changed — coloured green (fresh), amber (3+ days), or red (5+
  days, clearly stalled).
- Pulls live from Jira through the Worker's `epic_issues` action (needs
  `GH_PROXY` / the Worker deployed — see `worker/SETUP.md`), including each
  issue's changelog.
- Every earlier day's status **isn't a Jira field, so nothing is saved
  anywhere**: each export checks Jira's own status-change history for what
  the status was at the end of that day. Every export is independent — no
  snapshot file, nothing to fall out of sync.
- Status cells are colour-coded (green = done, blue = in progress, amber =
  waiting/review, red = blocked), and the **Type** column uses the same
  colour family (green = Story, blue = Task, amber = Sub-task, red = Bug,
  purple = Epic) so the sheet reads as one consistent colour system. Cells
  for days before an issue existed show a grey dash (—).
- `EPIC_HISTORY_START` (format `yyyy-mm-dd`), near the top of the
  `exportEpicExcel()` function in `docs/index.html` (and `src/build_site.py`,
  so a future weekly rebuild doesn't revert it), only sets the *default*
  shown the first time someone opens the dialog — not a hard limit.
- To export a different epic, edit `EPIC_KEY` the same way, in both files.
- **After pulling this change, redeploy the Cloudflare Worker** (`wrangler
  deploy` from `worker/`) — the button won't work until the Worker knows the
  new `epic_issues` action.

---

## Running locally (optional, to test)

```bash
pip install -r requirements.txt
export JIRA_EMAIL=you@example.com
export JIRA_API_TOKEN=xxxx
export JIRA_BASE_URL=https://your-site.atlassian.net
export JIRA_PROJECT=YOURPROJECT
export DEEPSEEK_API_KEY=xxxx
python src/main.py
# open docs/index.html in your browser
```

---

## Files

| Path                          | Purpose                                  |
|-------------------------------|------------------------------------------|
| `src/fetch_jira.py`           | Pulls issues from Jira                    |
| `src/accountability.py`       | Resolves who is on the hook per issue (assignee vs. review-level reviewer) |
| `src/calculate.py`            | Completion % + week-over-week comparison  |
| `src/analyze.py`              | DeepSeek analysis                         |
| `src/build_site.py`           | Renders the HTML report                   |
| `src/main.py`                 | Runs all steps in order                   |
| `src/post_comments.py`        | Posts queued comments to Jira (overdue nudges) |
| `.github/workflows/comments.yml`| Workflow the "ðŸ’¬ Comment in Jira" button triggers |
| `data/history.json`           | Weekly snapshots (the comparison memory)  |
| `docs/index.html`             | The published report (auto-generated)     |
| `.github/workflows/weekly.yml`| The Tuesday schedule                      |
