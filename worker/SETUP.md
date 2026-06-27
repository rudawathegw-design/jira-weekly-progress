# Secure GitHub proxy — one-time setup (~10 min, free)

This moves your GitHub token **off the public dashboard** and into a tiny
Cloudflare Worker. Your team keeps logging in with the **same site password** —
nothing changes for them. Until you finish this, the dashboard works exactly as
before (token embedded). The moment you set `GH_PROXY_URL` (step 6), the next
build removes the token from the page and routes through the Worker.

---

## What you need
- A free **Cloudflare** account (no credit card): https://dash.cloudflare.com/sign-up
- Your existing **`SITE_PASSWORD`** (the dashboard login password).
- A **fine-grained GitHub PAT** (we'll create a fresh, minimal one in step 4).

---

## Step 1 — Create the Worker
1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Create Worker**.
2. Name it e.g. `github-proxy`. Click **Deploy** (the default code is fine for now).
3. Click **Edit code**. Delete everything, paste the contents of
   [`github-proxy.js`](./github-proxy.js), then **Deploy**.

## Step 2 — Set the public config (Variables)
Worker → **Settings** → **Variables and Secrets** → add two **plaintext** vars:
| Name | Value |
|------|-------|
| `REPO` | `rudawathegw-design/jira-weekly-progress` |
| `ALLOWED_ORIGIN` | `https://rudawathegw-design.github.io` |

## Step 3 — Set the secrets (encrypted)
Same screen, add two **secret** (encrypted) values:
| Name | Value |
|------|-------|
| `SITE_PASSWORD` | the **same** password your dashboard uses |
| `GH_PAT` | the fine-grained token from step 4 |

## Step 4 — Create a minimal GitHub token
1. GitHub → **Settings** → **Developer settings** → **Fine-grained tokens** →
   **Generate new token**.
2. **Resource owner:** you. **Repository access:** *Only select repositories* →
   pick **`jira-weekly-progress`** only.
3. **Permissions** → Repository permissions:
   - **Contents:** Read and write
   - **Actions:** Read and write
   - (leave everything else *No access* — especially **Workflows: No access**)
4. Generate, copy it, paste into the Worker's `GH_PAT` secret (step 3).
5. **Revoke your old broad PAT** afterwards.

## Step 5 — Copy the Worker URL
On the Worker's page, copy its URL, e.g.
`https://github-proxy.<your-subdomain>.workers.dev`.

## Step 6 — Turn it on
GitHub repo → **Settings** → **Secrets and variables** → **Actions** →
**New repository secret**:
| Name | Value |
|------|-------|
| `GH_PROXY_URL` | the Worker URL from step 5 |

Then **Actions** tab → run **Daily Progress Report** once (or wait for the next
cron). The rebuilt dashboard will now have **no token in it** and will route
through your Worker.

---

## How to verify it worked
- View source on the live dashboard and search for `ghp_` / `github_pat_` —
  there should be **nothing** (the page no longer carries a token).
- Log in and try **Refresh** / hide a person / add a recipient — all should work
  exactly as before.
- In the browser Network tab, GitHub calls now go to your `workers.dev` URL.

## Notes
- The Worker only allows reads, writes to `data/`, and dispatching the two known
  workflows. It **refuses** to touch `src/` or `.github/` — so even if the site
  password leaked, no one can use it to edit code and steal your Jira token.
- To rotate: change `SITE_PASSWORD` in **both** the GitHub secret and the Worker,
  and re-run the build (ask for the rekey helper so encrypted history isn't lost).
