/**
 * github-proxy  —  Cloudflare Worker
 *
 * Holds the GitHub PAT so it never lives in the public dashboard. The dashboard
 * sends the SITE password (the one every user already types) in the
 * X-Proxy-Auth header; this Worker verifies it, then performs a TIGHTLY
 * ALLOW-LISTED GitHub API call on the user's behalf using the secret PAT.
 *
 * Because the allow-list forbids touching workflows and source code, even a
 * leaked site password can only do benign app actions (read data, write the
 * encrypted data stores, trigger the two known workflows) — it can NEVER edit
 * code/workflows to exfiltrate your Jira token.
 *
 * ── Secrets (set with `wrangler secret put` or in the dashboard) ──
 *   GH_PAT         fine-grained PAT, this repo only, Contents:RW + Actions:RW
 *   SITE_PASSWORD  must equal the dashboard's SITE_PASSWORD
 * ── Vars (wrangler.toml [vars]) ──
 *   REPO            e.g. "rudawathegw-design/jira-weekly-progress"
 *   ALLOWED_ORIGIN  e.g. "https://rudawathegw-design.github.io"
 */

const GH = "https://api.github.com";

// ── Approval-routing fields ────────────────────────────────────────────────
// Who is ACTUALLY accountable for an issue right now. Once a task moves to
// "Revision Level 1/2" the assignee has handed off, and the person who must act
// is that level's reviewer. Mirrors src/fetch_jira.py + src/accountability.py.
// customfield_10520 ("Involved Users") is a participant list, not an approver —
// carried through for the exports but never used to decide accountability.
const LEVEL_FIELDS = { 1: "customfield_10784", 2: "customfield_10785" };
const APPROVALS_FIELD = "customfield_10092";
const INVOLVED_FIELD = "customfield_10520";
const JIRA_BASE_FIELDS =
  "summary,assignee,reporter,status,duedate,priority,issuetype,statuscategorychangedate,updated";
const JIRA_LIVE_FIELDS =
  `${JIRA_BASE_FIELDS},${LEVEL_FIELDS[1]},${LEVEL_FIELDS[2]},${APPROVALS_FIELD},${INVOLVED_FIELD}`;

// Keep only the user identity we actually render. Jira inlines four avatar URLs
// (~400 bytes) per user reference; on a 465-issue project that alone is most of
// the payload. Dropping them makes the live response SMALLER than it was before
// the approval fields were added, which matters on the every-10s refresh.
function slimUser(u) {
  if (!u || !u.accountId) return null;
  const out = { accountId: u.accountId, displayName: u.displayName || "" };
  if (u.emailAddress) out.emailAddress = u.emailAddress;   // Team Directory
  return out;
}

function slimUsers(v) {
  if (!v) return null;
  const arr = (Array.isArray(v) ? v : [v]).map(slimUser).filter(Boolean);
  return arr.length ? arr : null;
}

// The sd-approvals field carries a full approver object graph per approval.
// We need only: which level, whether it is still pending, and who owes it.
function slimApprovals(v) {
  if (!v) return null;
  const arr = (Array.isArray(v) ? v : [v])
    .map((a) => {
      if (!a || typeof a !== "object") return null;
      const approvers = (a.approvers || [])
        .map((x) => slimUser(x && x.approver))
        .filter(Boolean);
      return {
        name: a.name || "",
        finalDecision: a.finalDecision || "",
        approvers,
      };
    })
    .filter(Boolean);
  return arr.length ? arr : null;
}

// Strip a raw Jira issue down to exactly the shape the dashboard reads.
function slimIssue(i) {
  const f = i.fields || {};
  const st = f.status || {};
  const it = f.issuetype || {};
  const out = {
    key: i.key || "",
    fields: {
      summary: f.summary || "",
      duedate: f.duedate || null,
      updated: f.updated || null,
      statuscategorychangedate: f.statuscategorychangedate || null,
      assignee: slimUser(f.assignee),
      // At "Waiting For Approval" the reporter holds the task, so the live
      // path needs them for attribution - not just for display.
      reporter: slimUser(f.reporter),
      status: {
        name: st.name || "",
        statusCategory: { key: ((st.statusCategory || {}).key) || "" },
      },
      issuetype: { name: it.name || "", subtask: !!it.subtask },
      priority: f.priority ? { name: f.priority.name || "" } : null,
    },
  };
  const l1 = slimUsers(f[LEVEL_FIELDS[1]]);
  const l2 = slimUsers(f[LEVEL_FIELDS[2]]);
  const ap = slimApprovals(f[APPROVALS_FIELD]);
  const iv = slimUsers(f[INVOLVED_FIELD]);
  if (l1) out.fields[LEVEL_FIELDS[1]] = l1;
  if (l2) out.fields[LEVEL_FIELDS[2]] = l2;
  if (ap) out.fields[APPROVALS_FIELD] = ap;
  if (iv) out.fields[INVOLVED_FIELD] = iv;
  return out;
}

function cors(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Proxy-Auth, X-Comment-Auth",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

// Constant-time string compare (avoid timing oracle on the password).
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Identify operations that POST comments to Jira. These require an EXTRA
// password (X-Comment-Auth) on top of the site password — so even a user who
// knows the site password cannot post comments without the comment password.
function isCommentOp(method, path, repo) {
  const base = `/repos/${repo}`;
  const p = path.split("?")[0];
  const sub = p.slice(base.length);
  // Dispatching the comments workflow, or writing the comment queue store.
  if (method === "POST" && /^\/actions\/workflows\/comments\.yml\/dispatches$/.test(sub)) return true;
  if ((method === "PUT" || method === "DELETE") &&
      /^\/contents\/data\/comment_queue\.json\.enc$/.test(sub)) return true;
  return false;
}

// Decide whether (method, path) is allowed for this repo. Returns true/false.
function isAllowed(method, path, repo) {
  const base = `/repos/${repo}`;
  // Strip query string for matching.
  const p = path.split("?")[0];
  if (!p.startsWith(base + "/") && p !== base) return false;
  const sub = p.slice(base.length); // e.g. "/contents/data/history.json.enc"

  if (method === "GET") {
    // Read-only: contents, commits, actions runs/workflows — all safe to read.
    return /^\/(contents\/|commits\/|commits$|actions\/runs|actions\/workflows\/)/.test(sub) || sub === "";
  }
  if (method === "POST") {
    // Dispatch the two known workflows, or cancel a workflow run (used by the
    // dashboard's "Cancel queued batch"). Cancelling only stops a run — safe.
    return /^\/actions\/workflows\/(weekly|comments)\.yml\/dispatches$/.test(sub)
        || /^\/actions\/runs\/\d+\/cancel$/.test(sub);
  }
  if (method === "PUT" || method === "DELETE") {
    // Writes are confined to data/ (encrypted stores, schedule, temp email
    // images). NEVER source code or workflow files — so a leaked site password
    // can't inject code to exfiltrate the Jira secret.
    return /^\/contents\/data\//.test(sub);
  }
  return false;
}

export default {
  // ── Backup cron pinger ────────────────────────────────────────────────
  // GitHub's own scheduler is unreliable and the external pinger
  // (cron-job.org) is a single point of failure. This Cloudflare cron
  // trigger (wrangler.toml [triggers]) fires repository_dispatch
  // event_type=cron_ping every 5 minutes as a redundant tick source. The
  // repo's `decide` job stays the single source of truth for whether a
  // tick actually runs/saves, so overlapping pingers are harmless.
  async scheduled(event, env, ctx) {
    const r = await fetch(`${GH}/repos/${env.REPO}/dispatches`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.GH_PAT}`,
        "Accept": "application/vnd.github+json",
        "User-Agent": "github-proxy-cron-pinger",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ event_type: "cron_ping" }),
    });
    // 204 = dispatched. Log failures so they show in the Worker's dashboard.
    if (r.status !== 204) {
      console.error(`cron_ping dispatch failed: ${r.status} ${await r.text()}`);
    }
  },

  async fetch(request, env, ctx) {
    // Everything below runs inside a guard. Without it, any thrown error kills
    // the isolate: the connection drops with no HTTP status and the dashboard
    // can only report "Failed to fetch", which says nothing about the cause.
    // Wrapped, a thrown error comes back as a readable 500 instead.
    //
    // Note what this deliberately cannot catch: exceeding the CPU limit is not
    // an exception, it terminates the isolate. So a dropped connection that
    // survives this guard is itself the diagnosis — it means CPU, not a bug.
    try {
      return await handleRequest(request, env, ctx);
    } catch (err) {
      const msg = (err && (err.stack || err.message)) || String(err);
      console.error("[worker] unhandled", msg);
      const allow = (env.ALLOWED_ORIGIN || "").split(",").map(s => s.trim()).filter(Boolean);
      const origin = request.headers.get("Origin");
      const corsOrigin = (origin && (allow.length === 0 || allow.includes(origin))) ? origin : (allow[0] || "*");
      return new Response(JSON.stringify({
        message: "Worker error",
        detail: String(msg).slice(0, 500),
      }), { status: 500, headers: { ...cors(corsOrigin), "Content-Type": "application/json" } });
    }
  },
};

async function handleRequest(request, env, ctx) {
    // ALLOWED_ORIGIN may be a comma-separated list (e.g. the custom domain plus
    // the github.io fallback). Echo back the caller's origin when it's allowed.
    const allowList = (env.ALLOWED_ORIGIN || "")
      .split(",").map((s) => s.trim()).filter(Boolean);
    const reqOrigin = request.headers.get("Origin");
    const originAllowed = allowList.length === 0 ||
      (reqOrigin && allowList.includes(reqOrigin));
    const corsOrigin = (reqOrigin && originAllowed) ? reqOrigin : (allowList[0] || "*");
    const baseHeaders = cors(corsOrigin);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: baseHeaders });
    }
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405, headers: baseHeaders });
    }
    // Reject cross-origin callers that aren't an allowed dashboard origin.
    if (allowList.length && reqOrigin && !originAllowed) {
      return new Response("Forbidden origin", { status: 403, headers: baseHeaders });
    }

    // ── Authenticate with the site password (dashboard) OR the admin password
    // (admin panel). Both are accepted so the admin panel can use its own
    // separate password without exposing the dashboard's SITE_PASSWORD. ──
    let auth = request.headers.get("X-Proxy-Auth") || "";
    auth = auth.replace(/^Bearer\s+/i, "").replace(/^token\s+/i, "").trim();
    const _okSite  = env.SITE_PASSWORD  && safeEqual(auth, env.SITE_PASSWORD);
    const _okAdmin = env.ADMIN_PASSWORD && safeEqual(auth, env.ADMIN_PASSWORD);
    if (!_okSite && !_okAdmin) {
      // Small delay blunts online brute-forcing.
      await new Promise((r) => setTimeout(r, 400));
      return new Response(JSON.stringify({ message: "Unauthorized" }), {
        status: 401, headers: { ...baseHeaders, "Content-Type": "application/json" },
      });
    }

    const json = (s, o) => new Response(JSON.stringify(o), {
      status: s, headers: { ...baseHeaders, "Content-Type": "application/json" },
    });

    let body;
    try { body = await request.json(); } catch { body = {}; }

    // ── Password verification (no GitHub call) ──
    // The page gates (Admin panel + Restricted popup) send the typed password
    // here to validate it SERVER-SIDE, so no password is hardcoded in the
    // public page. Reaching this point means auth already passed (else 401),
    // so we only need to report WHICH credential matched.
    if (body.action === "verify") {
      return json(200, { ok: true, role: _okAdmin ? "admin" : "site" });
    }

    // ── Portfolio rollup: per-project counts across ALL accessible projects ──
    // Minimal fields, aggregated SERVER-SIDE so the response is tiny (counts
    // only, not raw issues) — cheap on Worker CPU and bandwidth.
    if (body.action === "portfolio") {
      if (!env.JIRA_EMAIL || !env.JIRA_API_TOKEN) {
        return json(501, { message: "Jira not configured in Worker" });
      }
      const baseUrl = String(env.JIRA_BASE_URL || "https://fibtask.atlassian.net").replace(/\/+$/, "");
      const jauth = btoa(`${env.JIRA_EMAIL}:${env.JIRA_API_TOKEN}`);
      const jhdr = { Accept: "application/json", Authorization: `Basic ${jauth}` };
      // Accessible projects (key + name).
      let projs = [], pstart = 0;
      for (let i = 0; i < 10; i++) {
        const pr = await fetch(`${baseUrl}/rest/api/3/project/search?maxResults=50&startAt=${pstart}`, { headers: jhdr });
        if (!pr.ok) { const t = await pr.text(); return json(502, { message: "Jira API error", status: pr.status, detail: t.slice(0, 300) }); }
        const pd = await pr.json();
        (pd.values || []).forEach((p) => projs.push({ key: p.key, name: p.name }));
        if (pd.isLast || !(pd.values || []).length) break;
        pstart += 50;
      }
      // Exact counts via the count API (one tiny call per metric — no paging,
      // no truncation, minimal CPU). 3 calls/project keeps us under the cap.
      const countOf = async (jql) => {
        try {
          const r = await fetch(`${baseUrl}/rest/api/3/search/approximate-count`, {
            method: "POST", headers: { ...jhdr, "Content-Type": "application/json" },
            body: JSON.stringify({ jql }),
          });
          if (!r.ok) return null;
          const d = await r.json();
          return typeof d.count === "number" ? d.count : null;
        } catch (e) { return null; }
      };
      const out = [];
      for (const p of projs) {
        const k = p.key;
        const total = await countOf(`project = "${k}"`);
        const done = await countOf(`project = "${k}" AND statusCategory = Done`);
        const overdue = await countOf(`project = "${k}" AND statusCategory != Done AND duedate < now()`);
        out.push({ key: k, name: p.name, total, done, overdue });
      }
      const grand = out.reduce((a, p) => a + (p.total || 0), 0);
      return json(200, { projects: out, total: grand });
    }

    // ── One project's issues (drill-down task list) — minimal fields, no
    // changelog (CPU-safe). project key required. ──
    if (body.action === "issues") {
      if (!env.JIRA_EMAIL || !env.JIRA_API_TOKEN) {
        return json(501, { message: "Jira not configured in Worker" });
      }
      const proj = String(body.project || "").trim().replace(/[^A-Za-z0-9_]/g, "");
      if (!proj) return json(400, { message: "project key required" });
      const baseUrl = String(env.JIRA_BASE_URL || "https://fibtask.atlassian.net").replace(/\/+$/, "");
      const jauth = btoa(`${env.JIRA_EMAIL}:${env.JIRA_API_TOKEN}`);
      const jql = `project = "${proj}" ORDER BY updated DESC`;
      let issues = [], token = null;
      for (let i = 0; i < 20; i++) {           // cap ~2000 (biggest project < 1000)
        const qs = new URLSearchParams({
          jql, maxResults: "100",
          fields: "summary,assignee,status,duedate,issuetype,priority,updated",
        });
        if (token) qs.set("nextPageToken", token);
        const jr = await fetch(`${baseUrl}/rest/api/3/search/jql?${qs}`, {
          headers: { Accept: "application/json", Authorization: `Basic ${jauth}` },
        });
        if (!jr.ok) { const t = await jr.text(); return json(502, { message: "Jira API error", status: jr.status, detail: t.slice(0, 300) }); }
        const d = await jr.json();
        issues = issues.concat(d.issues || []);
        token = d.nextPageToken;
        if (!token || d.isLast) break;
      }
      return json(200, { project: proj, issues });
    }

    // ── Cross-project activity: issues changed in the last N days (all
    // projects), WITH changelog. On-demand only; small window keeps it light. ──
    if (body.action === "activity_all") {
      if (!env.JIRA_EMAIL || !env.JIRA_API_TOKEN) {
        return json(501, { message: "Jira not configured in Worker" });
      }
      const baseUrl = String(env.JIRA_BASE_URL || "https://fibtask.atlassian.net").replace(/\/+$/, "");
      const jauth = btoa(`${env.JIRA_EMAIL}:${env.JIRA_API_TOKEN}`);
      const days = Math.min(Math.max(parseInt(body.days) || 1, 1), 3);
      const jql = `updated >= -${days}d ORDER BY updated DESC`;
      let issues = [], token = null;
      for (let i = 0; i < 4; i++) {            // cap ~200 recently-changed issues
        const qs = new URLSearchParams({
          jql, maxResults: "50",
          fields: "summary,assignee,status,project,issuetype",
          expand: "changelog",
        });
        if (token) qs.set("nextPageToken", token);
        const jr = await fetch(`${baseUrl}/rest/api/3/search/jql?${qs}`, {
          headers: { Accept: "application/json", Authorization: `Basic ${jauth}` },
        });
        if (!jr.ok) { const t = await jr.text(); return json(502, { message: "Jira API error", status: jr.status, detail: t.slice(0, 300) }); }
        const d = await jr.json();
        issues = issues.concat(d.issues || []);
        token = d.nextPageToken;
        if (!token || d.isLast) break;
      }
      return json(200, { issues });
    }

    // ── List Jira projects the token can access (read-only) ──
    if (body.action === "projects") {
      if (!env.JIRA_EMAIL || !env.JIRA_API_TOKEN) {
        return json(501, { message: "Jira not configured in Worker" });
      }
      const baseUrl = String(env.JIRA_BASE_URL || "https://fibtask.atlassian.net").replace(/\/+$/, "");
      const jauth = btoa(`${env.JIRA_EMAIL}:${env.JIRA_API_TOKEN}`);
      let values = [], start = 0;
      for (let i = 0; i < 20; i++) {
        const jr = await fetch(`${baseUrl}/rest/api/3/project/search?maxResults=50&startAt=${start}`, {
          headers: { Accept: "application/json", Authorization: `Basic ${jauth}` },
        });
        if (!jr.ok) {
          const t = await jr.text();
          return json(502, { message: "Jira API error", status: jr.status, detail: t.slice(0, 300) });
        }
        const d = await jr.json();
        (d.values || []).forEach((p) => values.push({ key: p.key, name: p.name, type: p.projectTypeKey }));
        if (d.isLast || !(d.values || []).length) break;
        start += 50;
      }
      return json(200, { projects: values });
    }

    // ── Live Jira fetch (powers the dynamic dashboard) ──
    // Read-only: pulls the project's issues with the Jira token (Worker secret).
    if (body.action === "jira") {
      // The dashboard polls this every 10 seconds, per open tab. Each miss
      // means several Jira pages fetched, parsed and slimmed — the most
      // expensive thing this Worker does on a routine basis, and the reason a
      // tick landing on top of an export could exhaust the CPU budget.
      //
      // A short shared cache collapses all of that: whoever arrives first pays
      // for the pull, everyone within the window gets the already-serialised
      // bytes back with almost no CPU spent. 15s is under the 10s poll by
      // design — the data is still live, the Worker just stops re-deriving it
      // for every viewer.
      const _liveCache = caches.default;
      const _liveKey = new Request(
        `https://live-cache.invalid/jira?p=${encodeURIComponent(String(env.JIRA_PROJECT || ""))}`,
        { method: "GET" });
      if (!body.fresh) {
        const hit = await _liveCache.match(_liveKey);
        if (hit) {
          return new Response(await hit.text(), {
            status: 200,
            headers: { ...baseHeaders, "Content-Type": "application/json", "X-Cache": "HIT" },
          });
        }
      }
      if (!env.JIRA_EMAIL || !env.JIRA_API_TOKEN) {
        return json(501, { message: "Jira not configured in Worker" });
      }
      const baseUrl = String(env.JIRA_BASE_URL || "https://fibtask.atlassian.net").replace(/\/+$/, "");
      const project = String(env.JIRA_PROJECT || "").trim();
      const jauth = btoa(`${env.JIRA_EMAIL}:${env.JIRA_API_TOKEN}`);
      // Quote the project key, and when none is configured fall back to a valid
      // all-issues query (an unquoted/empty project makes Jira reject the JQL).
      const jql = project
        ? `project = "${project}" ORDER BY created DESC`
        : `ORDER BY created DESC`;
      let issues = [], token = null;
      for (let i = 0; i < 80; i++) {           // safety cap (8000 issues)
        // NOTE: do NOT expand "changelog" here. With ~hundreds of issues the
        // changelog payload is huge and blows the Worker CPU budget (Cloudflare
        // error 1102 → 503 → "Failed to fetch" in the dashboard). The live view
        // only needs current status/dates; the weekly Python build still pulls
        // changelog for the Activity Log on the published page.
        const qs = new URLSearchParams({
          jql, maxResults: "100",
          // Includes the Level 1/2 Reviewer + Approvals fields so the dashboard
          // can attribute an in-review task to its reviewer, not its assignee.
          fields: JIRA_LIVE_FIELDS,
        });
        if (token) qs.set("nextPageToken", token);
        const jr = await fetch(`${baseUrl}/rest/api/3/search/jql?${qs}`, {
          headers: { Accept: "application/json", Authorization: `Basic ${jauth}` },
        });
        if (!jr.ok) {
          const t = await jr.text();
          return json(502, { message: "Jira API error", status: jr.status, detail: t.slice(0, 300) });
        }
        const d = await jr.json();
        // Slim each page as it arrives so the accumulated array never holds the
        // full fat payload (keeps Worker memory + CPU well inside budget).
        issues = issues.concat((d.issues || []).map(slimIssue));
        token = d.nextPageToken;
        if (!token || d.isLast) break;
      }
      const _liveBody = JSON.stringify({ issues });
      // Cache-Control is what gives the entry its lifetime; waitUntil keeps the
      // write off the response path.
      const _toCache = new Response(_liveBody, {
        headers: { "Content-Type": "application/json", "Cache-Control": "max-age=15" },
      });
      if (ctx && ctx.waitUntil) ctx.waitUntil(_liveCache.put(_liveKey, _toCache));
      else await _liveCache.put(_liveKey, _toCache);
      return new Response(_liveBody, {
        status: 200,
        headers: { ...baseHeaders, "Content-Type": "application/json", "X-Cache": "MISS" },
      });
    }

    // ── Whole-project daily-status export ──
    // Same shape as epic_issues but for EVERY issue in the project. The plain
    // "jira" action deliberately skips changelog because the full payload blows
    // the Worker CPU budget (Cloudflare 1102 → 503). The daily-status matrix
    // only needs STATUS transitions, so we keep changelog but strip each history
    // down to its status items and drop every other field. On this project that
    // takes the response from ~10 MB to a few hundred KB.
    if (body.action === "project_issues") {
      if (!env.JIRA_EMAIL || !env.JIRA_API_TOKEN) {
        return json(501, { message: "Jira not configured in Worker" });
      }
      const baseUrl = String(env.JIRA_BASE_URL || "https://fibtask.atlassian.net").replace(/\/+$/, "");
      const project = String(env.JIRA_PROJECT || "").trim();
      const jauth = btoa(`${env.JIRA_EMAIL}:${env.JIRA_API_TOKEN}`);
      const jhdr = { Accept: "application/json", Authorization: `Basic ${jauth}` };
      const jql = project
        ? `project = "${project}" ORDER BY created DESC`
        : `ORDER BY created DESC`;

      // Keep only status changes, and only the three parts _statusAsOf reads.
      const slimChangelog = (cl) => {
        const out = [];
        for (const h of ((cl && cl.histories) || [])) {
          const items = (h.items || [])
            .filter((it) => (it.field || "").toLowerCase() === "status")
            .map((it) => ({ field: "status", fromString: it.fromString || "", toString: it.toString || "" }));
          if (items.length) out.push({ created: h.created, items });
        }
        return { histories: out };
      };

      // ── One page per invocation ──────────────────────────────────────────
      // Paging used to happen inside this handler: up to 40 sequential Jira
      // fetches, each expanded with changelog, parsed and slimmed in a single
      // Worker invocation. On this project that is ~10 MB of JSON per run and
      // it exceeded the CPU limit (Cloudflare 1102), which reaches the browser
      // as a bare "Failed to fetch" because the connection dies mid-response.
      //
      // The client now drives the loop: it calls with `paged:true` and feeds
      // back the nextPageToken until done. Each invocation handles at most 100
      // issues, which keeps CPU well inside budget and spreads the Jira calls
      // out instead of firing them back-to-back.
      const paged = body.paged === true;
      const maxPages = paged ? 1 : 40;         // legacy path keeps the old cap

      let issues = [], token = body.pageToken || null, isLast = false;
      for (let i = 0; i < maxPages; i++) {
        const qs = new URLSearchParams({
          jql, maxResults: "100", fields: JIRA_LIVE_FIELDS, expand: "changelog",
        });
        if (token) qs.set("nextPageToken", token);
        const jr = await fetch(`${baseUrl}/rest/api/3/search/jql?${qs}`, { headers: jhdr });
        if (!jr.ok) {
          const t = await jr.text();
          // Surface Jira's own throttling verbatim: a 429 here means the token
          // budget is spent, and the client needs to back off rather than retry.
          return json(502, {
            message: jr.status === 429 ? "Jira rate limit" : "Jira API error",
            status: jr.status,
            retryAfter: jr.headers.get("Retry-After") || "",
            detail: t.slice(0, 300),
          });
        }
        const d = await jr.json();
        // Slim per page so the accumulator never holds the fat payload.
        for (const raw of (d.issues || [])) {
          const s = slimIssue(raw);
          s.changelog = slimChangelog(raw.changelog);
          issues.push(s);
        }
        token = d.nextPageToken || null;
        isLast = !token || d.isLast === true;
        if (isLast) break;
      }
      return json(200, {
        issues, project: project || "",
        nextPageToken: isLast ? null : token,
        isLast: paged ? isLast : true,
      });
    }

    // ── Epic export: all direct children of an epic + their subtasks ──
    // Powers the "Export Epic Excel" button. Two JQL passes: (1) the epic's
    // direct children (tries the modern "parent" link first, falls back to
    // classic "Epic Link" if that returns nothing), then (2) any subtasks of
    // those children. Read-only, same Jira secret as the other actions.
    if (body.action === "epic_issues") {
      if (!env.JIRA_EMAIL || !env.JIRA_API_TOKEN) {
        return json(501, { message: "Jira not configured in Worker" });
      }
      const baseUrl = String(env.JIRA_BASE_URL || "https://fibtask.atlassian.net").replace(/\/+$/, "");
      const epicKey = String(body.epicKey || "FIBTMP-489").trim();
      const jauth = btoa(`${env.JIRA_EMAIL}:${env.JIRA_API_TOKEN}`);
      const jhdr = { Accept: "application/json", Authorization: `Basic ${jauth}` };
      const fields = "summary,assignee,status,issuetype,parent,duedate,created,customfield_10784,customfield_10785,customfield_10092,customfield_10520";
      // expand=changelog is what lets the dashboard compute "yesterday's
      // status" by CHECKING Jira's own status-change history instead of us
      // saving a snapshot file anywhere. Safe here (unlike the whole-project
      // "jira" action above) because an epic's issue count is small.

      // Page cap is lower than the whole-project handler because an epic is
      // small; the client still drives the outer loop for the project export.
      async function runJql(jql) {
        let out = [], token = null;
        for (let i = 0; i < 20; i++) {          // safety cap (~2000 issues)
          const qs = new URLSearchParams({ jql, maxResults: "100", fields, expand: "changelog" });
          if (token) qs.set("nextPageToken", token);
          const jr = await fetch(`${baseUrl}/rest/api/3/search/jql?${qs}`, { headers: jhdr });
          if (!jr.ok) {
            const t = await jr.text();
            return { error: true, status: jr.status, detail: t.slice(0, 300),
                     retryAfter: jr.headers.get("Retry-After") || "" };
          }
          const d = await jr.json();
          out = out.concat(d.issues || []);
          token = d.nextPageToken;
          if (!token || d.isLast) break;
        }
        return { issues: out };
      }

      let direct = await runJql(`parent = "${epicKey}"`);
      if (direct.error) {
        return json(502, { message: "Jira API error", status: direct.status, detail: direct.detail });
      }
      if (!direct.issues.length) {
        const alt = await runJql(`"Epic Link" = "${epicKey}"`);
        if (!alt.error) direct = alt;
      }

      const directKeys = direct.issues.map((i) => i.key);
      let subtasks = [];
      if (directKeys.length) {
        const quoted = directKeys.map((k) => `"${k}"`).join(",");
        const sub = await runJql(`parent in (${quoted})`);
        if (!sub.error) subtasks = sub.issues;
      }

      const seen = new Set();
      const all = [];
      for (const i of [...direct.issues, ...subtasks]) {
        if (seen.has(i.key)) continue;
        seen.add(i.key);
        all.push(i);
      }
      return json(200, { epicKey, issues: all });
    }

    // ── Activity feed: changelog for recently-updated issues only ──
    // Separate, ON-DEMAND action (called when the Activity Log opens), so the
    // heavy changelog parse never runs on the every-10s live path. Kept small
    // (recent window + low page cap) to stay within the Worker CPU budget.
    if (body.action === "activity") {
      if (!env.JIRA_EMAIL || !env.JIRA_API_TOKEN) {
        return json(501, { message: "Jira not configured in Worker" });
      }
      const baseUrl = String(env.JIRA_BASE_URL || "https://fibtask.atlassian.net").replace(/\/+$/, "");
      const project = String(env.JIRA_PROJECT || "").trim();
      const jauth = btoa(`${env.JIRA_EMAIL}:${env.JIRA_API_TOKEN}`);
      const days = Math.min(Math.max(parseInt(body.days) || 2, 1), 7);
      const jql = project
        ? `project = "${project}" AND updated >= -${days}d ORDER BY updated DESC`
        : `updated >= -${days}d ORDER BY updated DESC`;
      let issues = [], token = null;
      for (let i = 0; i < 2; i++) {            // cap ~100 recent issues
        const qs = new URLSearchParams({
          jql, maxResults: "50",
          fields: "summary,assignee,status,duedate,issuetype,statuscategorychangedate,updated",
          expand: "changelog",
        });
        if (token) qs.set("nextPageToken", token);
        const jr = await fetch(`${baseUrl}/rest/api/3/search/jql?${qs}`, {
          headers: { Accept: "application/json", Authorization: `Basic ${jauth}` },
        });
        if (!jr.ok) {
          const t = await jr.text();
          return json(502, { message: "Jira API error", status: jr.status, detail: t.slice(0, 300) });
        }
        const d = await jr.json();
        issues = issues.concat(d.issues || []);
        token = d.nextPageToken;
        if (!token || d.isLast) break;
      }
      return json(200, { issues });
    }

    // ── DeepSeek chat (powers the "Ask AI" overlay) ──
    // Read-only relay: forwards the page's messages to DeepSeek using the
    // DEEPSEEK_API_KEY secret. The key NEVER reaches the browser.
    if (body.action === "deepseek") {
      if (!env.DEEPSEEK_API_KEY) {
        return json(501, { message: "DeepSeek not configured in Worker" });
      }
      const messages = Array.isArray(body.messages) ? body.messages : [];
      if (!messages.length) return json(400, { message: "No messages" });
      const dr = await fetch("https://api.deepseek.com/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${env.DEEPSEEK_API_KEY}`,
        },
        body: JSON.stringify({
          model: "deepseek-chat",
          messages,
          temperature: 0.3,
          max_tokens: 800,
          stream: false,
        }),
      });
      if (!dr.ok) {
        const t = await dr.text();
        return json(502, { message: "DeepSeek API error", status: dr.status, detail: t.slice(0, 300) });
      }
      const d = await dr.json();
      const reply = (((d.choices || [])[0] || {}).message || {}).content || "";
      return json(200, { reply });
    }

    const path = String(body.path || "");
    const method = String(body.method || "GET").toUpperCase();
    const ghBody = body.ghBody != null ? body.ghBody : undefined; // original request body string

    if (!path.startsWith("/repos/") || !isAllowed(method, path, env.REPO)) {
      return new Response(JSON.stringify({ message: "Operation not allowed by proxy", path, method }), {
        status: 403, headers: { ...baseHeaders, "Content-Type": "application/json" },
      });
    }

    // ── Comment ops need the SECOND password (server-side, can't be bypassed) ──
    // Accepts the ADMIN_PASSWORD (so the admin password also authorizes posting
    // comments) or a dedicated COMMENT_PASSWORD if one is configured. The
    // password lives ONLY in Worker secrets — never in the page or repo.
    if (isCommentOp(method, path, env.REPO)) {
      if (!env.ADMIN_PASSWORD && !env.COMMENT_PASSWORD) {
        return json(501, { message: "Comment posting not configured (set ADMIN_PASSWORD or COMMENT_PASSWORD secret)" });
      }
      let cAuth = request.headers.get("X-Comment-Auth") || "";
      cAuth = cAuth.replace(/^Bearer\s+/i, "").replace(/^token\s+/i, "").trim();
      const okComment =
        (env.ADMIN_PASSWORD   && safeEqual(cAuth, env.ADMIN_PASSWORD)) ||
        (env.COMMENT_PASSWORD && safeEqual(cAuth, env.COMMENT_PASSWORD));
      if (!okComment) {
        await new Promise((r) => setTimeout(r, 400)); // blunt brute-forcing
        return json(401, { message: "Admin password required or incorrect" });
      }
    }

    // ── Forward to GitHub with the secret PAT ──
    const ghResp = await fetch(GH + path, {
      method,
      headers: {
        "Authorization": `Bearer ${env.GH_PAT}`,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "jira-weekly-progress-proxy",
      },
      body: (method === "GET" || method === "HEAD") ? undefined : ghBody,
    });

    const text = await ghResp.text();
    return new Response(text, {
      status: ghResp.status,
      headers: { ...baseHeaders, "Content-Type": ghResp.headers.get("Content-Type") || "application/json" },
    });
  }
