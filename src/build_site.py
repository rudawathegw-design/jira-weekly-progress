"""
build_site.py  —  renders docs/index.html + docs/admin.html
Env vars:  SITE_PASSWORD_HASH, SITE_PASSWORD, GH_PAT, GITHUB_REPOSITORY

Sensitive data (report, AI analysis, GitHub PAT) is encrypted with AES-GCM
using a key derived via PBKDF2 from SITE_PASSWORD. HTML source contains only
opaque base64 ciphertext — nothing readable in DevTools until the user
enters the correct password.
"""

import os, json, base64, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DOCS_DIR = os.path.join(os.path.dirname(__file__), "..", "docs")
PBKDF2_ITERATIONS = 1_000_000   # Above the OWASP floor — extra margin for offline brute-force of the embedded report blob (the site password is fixed/shared, so we buy strength with iterations). ~0.5s unlock on modern devices; old blobs still decrypt via their stored iter count.


def encrypt_payload(plaintext: str, password: str) -> dict:
    """AES-GCM encrypt; key = PBKDF2-SHA256(password, salt, PBKDF2_ITERATIONS)."""
    salt  = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=PBKDF2_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return {
        "salt":  base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct":    base64.b64encode(ct).decode(),
        "iter":  PBKDF2_ITERATIONS,
    }

# ─────────────────────────────────────────────────────────────────────────────
# index.html
# ─────────────────────────────────────────────────────────────────────────────
_INDEX = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="repo" content="__REPO__">
<meta name="gh-proxy" content="__GH_PROXY__">
<meta name="delete-hash" content="__DELETE_HASH__">
<title>Progress Report · __DATE__</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
html{font-size:14px;-webkit-text-size-adjust:100%}
body{
  font-family:'Inter',system-ui,sans-serif;color:#0f172a;line-height:1.5;
  min-height:100vh;
  /* Softer, calmer cloud-AI palette — Anthropic-cream meets soft sky */
  background:
    radial-gradient(ellipse 70% 50% at 10% -5%, hsla(210,100%,94%,.7), transparent 60%),
    radial-gradient(ellipse 50% 40% at 100% 10%, hsla(40,100%,93%,.6), transparent 65%),
    radial-gradient(ellipse 60% 45% at 50% 110%, hsla(155,80%,93%,.55), transparent 65%),
    linear-gradient(180deg, #fbfaf7 0%, #f7f6f1 100%);
  background-attachment:fixed;
  padding:clamp(12px,3vw,36px);
}
.wrap{max-width:1400px;margin:0 auto}

/* ── password overlay ────────────────────────────────────────── */
#pw-overlay{position:fixed;inset:0;
  background:
    radial-gradient(ellipse 70% 50% at 50% -10%, hsla(213,55%,92%,.9), transparent 60%),
    radial-gradient(ellipse 55% 45% at 88% 108%, hsla(155,50%,90%,.7), transparent 65%),
    linear-gradient(180deg,#fbfaf7,#f3f1ea);
  display:flex;align-items:center;justify-content:center;z-index:500;padding:20px}
.pw-card{background:#fff;border:1px solid #e8e4da;border-radius:26px;
  box-shadow:0 30px 70px -25px rgba(15,42,86,.25),0 6px 20px rgba(0,0,0,.05);
  padding:44px 48px 34px;width:min(420px,94vw);text-align:center}
.pw-brand{width:64px;height:64px;margin:0 auto 16px;border-radius:18px;display:grid;place-items:center;
  background:linear-gradient(135deg,#0a3b7c,#1366cc);color:#fff;font-weight:800;font-size:22px;
  letter-spacing:.02em;box-shadow:0 12px 28px -10px rgba(10,59,124,.55)}
.pw-kicker{font-size:10.5px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;
  color:#a39e8f;margin-bottom:8px}
.pw-card h2{font-size:23px;font-weight:800;letter-spacing:-.03em;margin-bottom:6px;color:#1b2a44}
.pw-card p{color:#6b7280;font-size:13px;margin-bottom:24px;line-height:1.5}
.pw-card .inp{text-align:center;letter-spacing:.08em;font-size:15px;padding:13px 46px 13px 46px;border-radius:12px}
.pw-card .inp:focus{border-color:#1366cc;box-shadow:0 0 0 3px rgba(19,102,204,.13)}
.pw-field{position:relative}
.pw-eye{position:absolute;right:7px;top:50%;transform:translateY(-50%);border:none;background:transparent;
  color:#94a3b8;font-size:11px;font-weight:700;letter-spacing:.05em;cursor:pointer;
  padding:7px 9px;border-radius:8px;font-family:inherit;text-transform:uppercase}
.pw-eye:hover{background:#f1f5f9;color:#334155}
.pw-card .btn-primary{background:linear-gradient(135deg,#0a3b7c,#1366cc);border-radius:12px;padding:13px;
  margin-top:12px;box-shadow:0 10px 24px -10px rgba(10,59,124,.5);
  transition:transform .15s,box-shadow .15s,opacity .2s}
.pw-card .btn-primary:hover{opacity:1;transform:translateY(-1px);
  box-shadow:0 14px 30px -10px rgba(10,59,124,.6)}
.pw-foot{margin-top:18px;font-size:11px;color:#a8a294;line-height:1.6}
.inp{width:100%;border:1.5px solid #e2e8f0;border-radius:10px;background:#f8fafc;
  color:#1e293b;font-size:15px;padding:11px 15px;outline:none;
  font-family:inherit;transition:border .2s,background .2s}
.inp:focus{border-color:#3b82f6;background:#fff;
  box-shadow:0 0 0 3px rgba(59,130,246,.12)}
.btn-primary{width:100%;
  background:linear-gradient(135deg,#3b82f6,#1d4ed8);
  color:#fff;font-weight:700;font-size:14px;border:none;border-radius:10px;
  padding:12px;cursor:pointer;letter-spacing:.02em;transition:opacity .2s;
  font-family:inherit;margin-top:11px}
.btn-primary:hover{opacity:.9}
.btn-primary:disabled{opacity:.5;cursor:not-allowed}
.err-msg{color:#dc2626;font-size:12px;margin-top:9px;min-height:16px}

/* ── modal overlay ───────────────────────────────────────────── */
.modal-overlay{position:fixed;inset:0;background:rgba(15,23,42,.45);
  backdrop-filter:blur(4px);display:flex;align-items:center;
  justify-content:center;z-index:400;padding:20px}
.modal-overlay.hidden{display:none}
.modal{background:#fff;border:1.5px solid #e2e8f0;border-radius:18px;
  box-shadow:0 24px 64px rgba(0,0,0,.18);
  padding:28px 30px;width:min(580px,96vw);max-height:90vh;overflow-y:auto}
.modal h3{font-size:17px;font-weight:800;letter-spacing:-.03em;margin-bottom:18px;
  display:flex;align-items:center;gap:8px}
.modal-section{margin-bottom:18px}
.modal-section-label{font-size:11px;font-weight:700;text-transform:uppercase;
  letter-spacing:.1em;color:#94a3b8;margin-bottom:8px}
.check-grid{display:flex;flex-wrap:wrap;gap:7px}
.check-item{display:inline-flex;align-items:center;gap:6px;
  background:#f8fafc;border:1.5px solid #e2e8f0;border-radius:8px;
  padding:6px 12px;cursor:pointer;font-size:12.5px;font-weight:600;
  color:#334155;transition:all .15s;user-select:none}
.check-item:hover{border-color:#94a3b8;background:#f1f5f9}
.check-item.on{background:#dbeafe;border-color:#93c5fd;color:#1d4ed8}
.check-item input[type=checkbox]{accent-color:#2563eb}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:20px}
.btn-modal{border:none;border-radius:8px;font-size:13px;font-weight:700;
  padding:9px 20px;cursor:pointer;font-family:inherit;transition:opacity .15s}
.btn-modal.blue{background:linear-gradient(135deg,#3b82f6,#1d4ed8);color:#fff}
.btn-modal.blue:hover{opacity:.9}
.btn-modal.green{background:linear-gradient(135deg,#059669,#047857);color:#fff;
  box-shadow:0 2px 8px rgba(5,150,105,.25)}
.btn-modal.green:hover{opacity:.9}
.btn-modal.ghost{background:#f1f5f9;color:#334155}
.btn-modal.ghost:hover{background:#e2e8f0}
.week-sel{border:1.5px solid #e2e8f0;border-radius:8px;background:#f8fafc;
  color:#1e293b;font-size:12.5px;padding:7px 10px;outline:none;
  font-family:'JetBrains Mono',monospace;cursor:pointer;
  transition:border .15s;margin-top:6px}
.week-sel:focus{border-color:#3b82f6}

/* ── people visibility toggles ───────────────────────────────── */
.vis-grid{display:flex;flex-wrap:wrap;gap:6px}
.vis-btn{display:inline-flex;align-items:center;gap:5px;
  background:#f0fdf4;border:1.5px solid #bbf7d0;border-radius:8px;
  padding:5px 11px;cursor:pointer;font-size:12px;font-weight:600;
  color:#166534;transition:all .15s;user-select:none;font-family:inherit}
.vis-btn:hover{opacity:.8}
.vis-btn.hidden-person{background:#fff5f5;border-color:#fecaca;color:#9f1239}

/* ── token modal ─────────────────────────────────────────────── */
#tok-modal .tok-hint{font-size:12px;color:#64748b;margin-top:8px;line-height:1.6}
#tok-modal .tok-hint a{color:#2563eb}

/* ── compare result ──────────────────────────────────────────── */
#cmp-wrap{margin-top:14px;overflow-x:auto}
#cmp-wrap table{width:100%;border-collapse:collapse;min-width:600px}
#cmp-wrap th{background:#f1f5f9;font-size:11px;font-weight:700;text-transform:uppercase;
  letter-spacing:.07em;color:#475569;padding:9px 11px;text-align:left;
  border-bottom:2px solid #cbd5e1}
#cmp-wrap td{padding:8px 11px;border-bottom:1px solid #f1f5f9;font-size:12.5px}
#cmp-wrap tr:last-child td{border-bottom:none}
.cmp-match{color:#059669;font-weight:700}
.cmp-diff{color:#dc2626;font-weight:700}
.cmp-missing{color:#94a3b8;font-style:italic}

/* ── top bar ─────────────────────────────────────────────────── */
.topbar{display:flex;align-items:center;justify-content:space-between;
  gap:12px;flex-wrap:wrap;margin-bottom:20px}
.brand-title{font-size:clamp(20px,4vw,26px);font-weight:800;
  letter-spacing:-.04em;color:#0f172a}
.brand-sub{font-size:13px;color:#0f172a;font-weight:700;letter-spacing:.02em;
  margin-top:3px;font-family:'JetBrains Mono',monospace}
.last-updated-badge{display:flex;align-items:center;gap:9px;
  background:linear-gradient(135deg,#dbeafe,#ede9fe);
  border:1.5px solid #bfdbfe;border-radius:12px;
  padding:8px 14px;box-shadow:0 2px 8px rgba(59,130,246,.15)}
.lu-dot{width:9px;height:9px;border-radius:50%;background:#10b981;
  box-shadow:0 0 0 4px rgba(16,185,129,.2);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 4px rgba(16,185,129,.2)}50%{box-shadow:0 0 0 6px rgba(16,185,129,.1)}}
.lu-label{font-size:9px;font-weight:800;color:#1e40af;letter-spacing:.12em;line-height:1}
.lu-date{font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:700;color:#0f172a;line-height:1.2;margin-top:2px}
.topbar-right{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.chip{display:inline-flex;align-items:center;gap:5px;background:#fff;
  border:1.5px solid #e2e8f0;border-radius:8px;color:#334155;
  font-size:12px;font-weight:600;padding:7px 12px;cursor:pointer;
  text-decoration:none;white-space:nowrap;transition:all .15s;
  font-family:inherit;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.chip:hover{border-color:#94a3b8;background:#f8fafc}
.chip.blue{background:linear-gradient(135deg,#3b82f6,#2563eb);
  color:#fff;border-color:transparent;box-shadow:0 2px 10px rgba(59,130,246,.3)}
.chip.blue:hover{opacity:.9}
.chip.green{background:linear-gradient(135deg,#059669,#047857);
  color:#fff;border-color:transparent;box-shadow:0 2px 10px rgba(5,150,105,.3)}
.chip.green:hover{opacity:.9}
.chip.chip-lg{font-size:13px;padding:9px 16px;font-weight:700}
.chip.chip-lg svg{width:14px;height:14px}
.chip[disabled],.chip.btn-loading{opacity:.7;cursor:wait;pointer-events:none}
/* ── Flat toolbar: muted icons, one filled primary, red-accent alert ──────── */
.chip svg{color:#64748b}
.chip.ac-red{color:#b91c1c;border-color:#fecaca}
.chip.ac-red svg{color:#dc2626}
.chip.ac-red:hover{background:#fef2f2;border-color:#fca5a5}
.chip.primary{background:linear-gradient(135deg,#0d9488,#0f766e);color:#fff;
  border-color:transparent;box-shadow:0 2px 10px rgba(13,148,136,.28)}
.chip.primary svg{color:#fff}
.chip.primary:hover{background:linear-gradient(135deg,#0f766e,#115e59);border-color:transparent}
/* LIVE freshness chip — pale green pill (warm/stale/loading states recolor it) */
#live-chip{background:#ecfdf5;border-color:#a7f3d0;color:#047857;
  box-shadow:none;cursor:default;gap:7px;font-size:12px}
#live-chip .live-dot{width:8px;height:8px;border-radius:50%;background:#10b981;
  animation:livePulseG 1.4s infinite;flex-shrink:0}
@keyframes livePulseG{0%,100%{box-shadow:0 0 0 3px rgba(16,185,129,.25)}50%{box-shadow:0 0 0 7px rgba(16,185,129,0)}}
#live-chip.loading,#live-chip.warm,#live-chip.stale{color:#fff}
#live-chip.loading .live-dot,#live-chip.warm .live-dot,#live-chip.stale .live-dot{
  background:#fff;animation:livePulse 1.4s infinite}
/* Mobile: action row becomes a horizontally scrollable tab strip */
@media (max-width:640px){
  .topbar-actions{flex-wrap:nowrap!important;overflow-x:auto;
    justify-content:flex-start!important;-webkit-overflow-scrolling:touch;
    scrollbar-width:none;padding-bottom:3px}
  .topbar-actions::-webkit-scrollbar{display:none}
  .topbar-actions>*{flex:0 0 auto}
}

/* spinner */
@keyframes spin{to{transform:rotate(360deg)}}
.spinner{animation:spin .85s linear infinite;transform-origin:center}
.refresh-progress{display:none;align-items:center;gap:7px;
  background:rgba(59,130,246,.12);border:1.5px solid rgba(59,130,246,.3);
  border-radius:8px;padding:5px 11px;font-size:11.5px;font-weight:600;color:#1e40af}
.refresh-progress.show{display:inline-flex}
.refresh-progress .spinner{color:#2563eb}

.hidden-indicator{display:inline-flex;align-items:center;gap:5px;
  background:rgba(217,119,6,.12);border:1.5px solid rgba(217,119,6,.35);
  border-radius:8px;padding:5px 11px;font-size:11.5px;font-weight:700;
  color:#92400e;font-family:'JetBrains Mono',monospace}
.hidden-indicator .hi-count{font-size:12.5px;font-weight:800;color:#78350f}

.last-run-chip{display:inline-flex;align-items:center;gap:6px;
  background:#fff;border:1.5px solid #e2e8f0;border-radius:8px;
  padding:5px 11px;font-size:11.5px;font-weight:600;color:#475569;
  text-decoration:none;cursor:pointer;transition:border-color .15s}
.last-run-chip:hover{border-color:#94a3b8}
.last-run-chip .lr-dot{width:7px;height:7px;border-radius:50%;background:#94a3b8;flex-shrink:0}
.last-run-chip.ok .lr-dot{background:#10b981;box-shadow:0 0 0 3px rgba(16,185,129,.2)}
.last-run-chip.fail .lr-dot{background:#dc2626;box-shadow:0 0 0 3px rgba(220,38,38,.2)}
.last-run-chip.run .lr-dot{background:#3b82f6;animation:pulse 1.5s infinite}
.last-run-chip .lr-txt{font-family:'JetBrains Mono',monospace}

/* "Save permanently" button in hide-people section */
.save-permanent-btn{display:inline-flex;align-items:center;gap:6px;
  background:linear-gradient(135deg,#3b82f6,#1d4ed8);color:#fff;
  border:none;border-radius:8px;padding:8px 14px;cursor:pointer;
  font-size:12px;font-weight:700;font-family:inherit;margin-top:10px;
  box-shadow:0 2px 8px rgba(59,130,246,.25);transition:opacity .15s}
.save-permanent-btn:hover{opacity:.92}
.save-permanent-btn[disabled]{opacity:.5;cursor:wait}
.persist-note{font-size:11.5px;color:#64748b;margin-top:6px;line-height:1.5}

/* Hide top-bar action buttons during canvas/Playwright capture */
body.capturing .topbar-right{display:none !important}

/* "More" dropdown menu */
.menu-dropdown{position:relative;display:inline-block}
.menu-items{display:none;position:absolute;top:calc(100% + 6px);right:0;
  min-width:260px;background:#fff;border:1.5px solid #e2e8f0;
  border-radius:12px;box-shadow:0 12px 32px rgba(0,0,0,.14),0 2px 8px rgba(0,0,0,.06);
  z-index:200;padding:6px;animation:menuPop .14s ease-out}
.menu-items.show{display:block}
@keyframes menuPop{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
.menu-section-label{font-size:9.5px;font-weight:800;color:#94a3b8;
  text-transform:uppercase;letter-spacing:.12em;padding:8px 12px 4px}
.menu-item{display:flex;align-items:center;gap:11px;width:100%;
  text-align:left;padding:9px 12px;border:none;background:transparent;
  cursor:pointer;border-radius:8px;font-family:inherit;color:#0f172a;
  transition:background .12s}
.menu-item:hover{background:#f1f5f9}
.menu-item svg{flex-shrink:0;color:#475569}
.menu-item-text{flex:1;min-width:0}
.menu-item-text > div:first-child{font-size:13px;font-weight:700;line-height:1.2}
.menu-item-sub{font-size:11px;color:#64748b;margin-top:1px}

/* ── stat cards ──────────────────────────────────────────────── */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
  gap:10px;margin-bottom:18px}
.stat{background:#fff;border:1px solid #e8eef5;border-radius:14px;
  padding:15px 17px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.stat .lbl{font-size:10px;font-weight:700;text-transform:uppercase;
  letter-spacing:.1em;color:#94a3b8;margin-bottom:5px}
.stat .val{font-size:26px;font-weight:800;letter-spacing:-.04em;line-height:1}
.stat .sub{font-size:11px;color:#94a3b8;margin-top:4px}
.val-green{color:#059669}.val-red{color:#dc2626}.val-blue{color:#2563eb}
.val-muted{color:#64748b}.val-amber{color:#d97706}

/* ── Analytics dashboard (donut + top/bottom) ────────────────── */
.analytics-card{background:#ffffff;
  border:1.5px solid #e2e8f0;border-radius:14px;
  box-shadow:0 6px 28px rgba(2,6,23,.06);
  padding:14px 22px 20px;margin-bottom:18px}
.analytics-header{display:flex;align-items:center;justify-content:space-between;
  gap:12px;padding-bottom:14px;margin-bottom:14px;border-bottom:1px solid #e8eef5}
.analytics-title{font-size:14px;font-weight:800;color:#0f172a;
  letter-spacing:-.01em;display:flex;align-items:center;gap:7px}
.analytics-actions{display:flex;gap:6px}
.analytics-card.collapsed .analytics-grid{display:none}
.analytics-card.collapsed{padding-bottom:14px}
.analytics-card.collapsed .analytics-header{margin-bottom:0;padding-bottom:0;border-bottom:none}
#analytics-chevron{transition:transform .25s}
.analytics-card.collapsed #analytics-chevron{transform:rotate(180deg)}
.analytics-grid{display:grid;grid-template-columns:280px 1fr;gap:32px;align-items:start}
.analytics-label{font-size:11px;font-weight:800;text-transform:uppercase;
  letter-spacing:.12em;color:#475569;margin-bottom:14px}
.analytics-donut{display:flex;flex-direction:column;align-items:flex-start}
.donut-legend{display:flex;flex-direction:column;gap:6px;margin-top:14px;width:100%}
.donut-row{display:flex;align-items:center;gap:8px;font-size:12.5px}
.donut-row-sw{width:12px;height:12px;border-radius:3px;flex-shrink:0}
.donut-row-name{flex:1;color:#334155}
.donut-row-val{font-family:'JetBrains Mono',monospace;font-weight:700;color:#0f172a}
.analytics-bars{min-width:0}

/* ── PMO Health Dashboard ────────────────────────────────────── */
.pmo-section{margin-bottom:16px}
.pmo-section:last-child{margin-bottom:0}
.pmo-section-title{font-size:10.5px;font-weight:800;color:#475569;
  text-transform:uppercase;letter-spacing:.12em;margin-bottom:7px;
  display:flex;align-items:center;gap:6px}

/* RAG stacked bar */
.rag-bar{display:flex;height:36px;border-radius:8px;overflow:hidden;
  border:1px solid #e2e8f0;background:#fafbfc}
.rag-seg{display:flex;align-items:center;justify-content:center;
  font-size:12.5px;font-weight:800;color:#fff;
  transition:flex .25s;min-width:0;padding:0 6px}
.rag-seg-g{background:linear-gradient(135deg,#34d399,#059669)}
.rag-seg-a{background:linear-gradient(135deg,#fbbf24,#d97706)}
.rag-seg-r{background:linear-gradient(135deg,#f87171,#dc2626)}
.rag-legend{display:flex;gap:14px;margin-top:7px;font-size:11.5px;color:#64748b;flex-wrap:wrap}
.rag-legend-dot{display:inline-block;width:9px;height:9px;border-radius:50%;
  vertical-align:middle;margin-right:5px}
.rag-legend strong{color:#0f172a}

/* KPI tiles */
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.kpi-tile{background:#fff;border:1.5px solid #e2e8f0;border-radius:9px;
  padding:9px 11px;min-width:0}
.kpi-tile-label{font-size:9.5px;font-weight:700;color:#64748b;
  text-transform:uppercase;letter-spacing:.08em;line-height:1.2}
.kpi-tile-value{font-size:20px;font-weight:800;color:#0f172a;
  font-family:'JetBrains Mono',monospace;line-height:1.1;margin-top:4px}
.kpi-tile-sub{font-size:10.5px;color:#94a3b8;line-height:1.2;margin-top:2px}
.kpi-good{color:#059669 !important}
.kpi-warn{color:#d97706 !important}
.kpi-bad{color:#dc2626 !important}

/* Escalation watchlist */
.esc-list{display:flex;flex-direction:column;gap:5px}
.esc-row{background:#fff;border:1px solid #e2e8f0;border-left:3px solid #ea7c2b;
  border-radius:6px;padding:7px 11px;display:flex;align-items:center;gap:10px;
  font-size:12.5px}
.esc-row.amber{border-left-color:#d97706}
.esc-rank{font-family:'JetBrains Mono',monospace;font-size:10.5px;font-weight:800;
  color:#94a3b8;width:18px}
.esc-name{font-weight:700;color:#0f172a;flex-shrink:0}
.esc-reasons{display:flex;gap:5px;flex-wrap:wrap;margin-left:auto}
.esc-chip{font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;
  background:#fff3e0;color:#b45309}
.esc-chip.amber{background:#fef3c7;color:#92400e}
.esc-chip.blue{background:#dbeafe;color:#1e40af}

/* Small transparent "show all / collapse" toggle under the watchlist */
.esc-toggle-btn{
  display:flex;align-items:center;justify-content:center;gap:5px;
  width:100%;margin-top:8px;padding:6px 10px;
  background:transparent;border:1px dashed #cbd5e1;border-radius:6px;
  color:#64748b;font-size:11.5px;font-weight:700;font-family:inherit;
  cursor:pointer;transition:background .15s ease,border-color .15s ease,color .15s ease;
}
.esc-toggle-btn:hover{background:#f8fafc;border-color:#94a3b8;color:#334155}
.esc-toggle-btn svg{flex-shrink:0}
@media(max-width:800px){.analytics-grid{grid-template-columns:1fr}}

/* ── AI section ──────────────────────────────────────────────── */
.ai-card{background:#fff;border:1.5px solid #e2e8f0;border-radius:14px;
  padding:18px 20px;margin-bottom:18px;
  box-shadow:0 2px 12px rgba(0,0,0,.05)}
.ai-header{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.ai-tag{font-size:10px;font-weight:700;text-transform:uppercase;
  letter-spacing:.12em;color:#2563eb;background:#dbeafe;
  border:1px solid #bfdbfe;border-radius:5px;padding:2px 7px}
.ai-date{font-size:11px;color:#94a3b8;margin-left:auto;
  font-family:'JetBrains Mono',monospace}
.ai-text{color:#334155;font-size:13px;line-height:1.75}
.ai-err{color:#dc2626;font-size:12px;font-style:italic}

/* ── risk alerts ─────────────────────────────────────────────── */
#risk-section{margin-bottom:18px;display:none}
.risk-title{font-size:11px;font-weight:700;text-transform:uppercase;
  letter-spacing:.1em;color:#b45309;margin-bottom:8px;
  display:flex;align-items:center;gap:6px}
.risk-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:8px}
.risk-card{background:#fffbeb;border:1px solid #fde68a;border-radius:10px;
  padding:12px 14px}
.risk-name{font-weight:700;font-size:13px;color:#92400e;margin-bottom:3px}
.risk-note{font-size:12px;color:#78350f;line-height:1.5}
.risk-tip{font-size:11.5px;color:#065f46;background:#ecfdf5;
  border:1px solid #a7f3d0;border-radius:6px;padding:4px 8px;margin-top:5px}

/* ── filter bar ──────────────────────────────────────────────── */
.filter-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;
  padding:11px 14px;background:#f8fafc;border-bottom:1px solid #e8eef5}
.search-wrap{position:relative;min-width:180px;max-width:280px}
.search-wrap svg{position:absolute;left:9px;top:50%;transform:translateY(-50%);
  color:#94a3b8;pointer-events:none}
.search-inp{width:100%;background:#fff;border:1.5px solid #e2e8f0;border-radius:8px;
  color:#1e293b;font-size:12.5px;padding:7px 10px 7px 30px;outline:none;
  font-family:inherit;transition:border .15s}
.search-inp:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.1)}
.filter-count{font-size:11.5px;color:#64748b;white-space:nowrap}
.clear-btn{display:none;align-items:center;gap:5px;font-size:12px;color:#fff;
  cursor:pointer;background:linear-gradient(135deg,#ef4444,#b91c1c);
  border:none;font-family:inherit;font-weight:700;padding:6px 12px;
  border-radius:8px;box-shadow:0 2px 6px rgba(220,38,38,.25);
  transition:opacity .15s,transform .1s}
.clear-btn:hover{opacity:.92}
.clear-btn:active{transform:translateY(1px)}
.clear-btn.show{display:inline-flex}

/* ── tab bar ─────────────────────────────────────────────────── */
.tab-bar{display:flex;gap:2px;padding:3px;background:#e8eef5;border-radius:10px;
  width:fit-content;margin-bottom:-1px;position:relative;z-index:1}
.tab-btn{background:transparent;border:none;font-family:inherit;font-size:12.5px;
  font-weight:600;color:#64748b;padding:7px 18px;border-radius:7px;
  cursor:pointer;transition:all .15s;white-space:nowrap}
.tab-btn.active{background:#fff;color:#1e293b;box-shadow:0 1px 4px rgba(0,0,0,.1)}

/* ── panel (filter bar wrapper) ──────────────────────────────── */
.panel{margin-bottom:18px}
.panel > .filter-bar{
  background:#ffffff;
  border:1.5px solid #e2e8f0;border-radius:14px;
  box-shadow:0 4px 18px rgba(2,6,23,.04);margin-bottom:14px}

/* ── stacked weekly layout (each table = own card with gap) ──── */
.three-col{display:flex;flex-direction:column;gap:14px}
.col-block{
  background:#ffffff;                  /* opaque — uniform row colors */
  border:1.5px solid #e2e8f0;border-radius:14px;
  box-shadow:0 6px 28px rgba(2,6,23,.06),0 1px 3px rgba(2,6,23,.03);
  overflow:hidden}
#tab-hist .col-block{margin-bottom:14px}
tbody tr.data-row{background:#ffffff}   /* every row uniformly white */
/* Big centered date banner — looks like the user's Excel header */
.col-hdr{padding:16px 24px;background:linear-gradient(180deg,#fafbfc,#f1f5f9);
  border-bottom:2px solid #cbd5e1;
  display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}
.col-hdr-label{display:flex;align-items:center;gap:9px;min-width:0}
.col-hdr-title{font-size:13px;font-weight:800;text-transform:uppercase;
  letter-spacing:.12em;color:#475569}
.col-hdr-date{font-family:'Inter',sans-serif;font-size:24px;
  font-weight:800;color:#0f172a;letter-spacing:-.02em;line-height:1;
  flex:1;text-align:center;min-width:120px}
.col-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.dot-blue{background:#3b82f6}.dot-slate{background:#94a3b8}.dot-amber{background:#f59e0b}
.baseline-sel{border:1.5px solid #cbd5e1;border-radius:8px;background:#fff;
  color:#1e293b;font-size:12px;font-weight:600;padding:6px 10px;
  font-family:'JetBrains Mono',monospace;cursor:pointer;
  transition:border-color .15s;max-width:240px;text-overflow:ellipsis}
.baseline-sel:focus{border-color:#3b82f6;outline:none;box-shadow:0 0 0 3px rgba(59,130,246,.12)}
.baseline-sel:hover{border-color:#94a3b8}

/* per-card action buttons (Copy + Export image) */
.col-hdr-actions{display:flex;align-items:center;gap:6px;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end}
.col-hdr-btn{background:rgba(255,255,255,.85);border:1.5px solid #e2e8f0;
  border-radius:7px;color:#475569;font-size:11px;font-weight:600;
  padding:5px 10px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;
  font-family:inherit;transition:all .15s;white-space:nowrap}
.col-hdr-btn:hover{border-color:#94a3b8;color:#0f172a;background:#fff}
.col-hdr-btn svg{flex-shrink:0}

/* History tab — colorful week dividers */
.week-divider{display:flex;align-items:center;gap:14px;padding:14px 22px;
  border-radius:12px;color:#fff;margin:22px 0 12px;
  box-shadow:0 6px 20px rgba(0,0,0,.12)}
.week-divider:first-child{margin-top:0}
.week-num-badge{font-size:18px;font-weight:800;letter-spacing:-.02em;
  background:rgba(255,255,255,.22);padding:5px 16px;border-radius:8px;
  border:1px solid rgba(255,255,255,.35)}
.week-divider-label{font-size:13px;font-weight:600;opacity:.95}
.week-date-big{font-family:'JetBrains Mono',monospace;font-size:16px;font-weight:800;
  margin-left:auto;background:rgba(255,255,255,.15);padding:5px 12px;border-radius:7px}
.week-color-0{background:linear-gradient(135deg,#3b82f6,#1e40af)}
.week-color-1{background:linear-gradient(135deg,#8b5cf6,#5b21b6)}
.week-color-2{background:linear-gradient(135deg,#06b6d4,#0e7490)}
.week-color-3{background:linear-gradient(135deg,#ec4899,#9f1239)}
.week-color-4{background:linear-gradient(135deg,#f59e0b,#92400e)}
.week-color-5{background:linear-gradient(135deg,#10b981,#065f46)}
.week-color-6{background:linear-gradient(135deg,#6366f1,#3730a3)}
.week-color-7{background:linear-gradient(135deg,#ef4444,#7f1d1d)}

/* ── tables ──────────────────────────────────────────────────── */
table{width:100%;border-collapse:collapse;min-width:340px}
.three-col table{min-width:320px}
/* full header labels by default; short labels (.lbl-abbr) only on mobile */
.lbl-abbr{display:none}
thead tr{background:linear-gradient(180deg,#f1f5f9,#e8eef5)}
thead th{font-size:10px;font-weight:700;text-transform:uppercase;
  letter-spacing:.07em;color:#475569;text-align:left;
  padding:9px 11px;border-bottom:2px solid #cbd5e1;white-space:nowrap}
thead th.c{text-align:center}
tbody td{padding:8px 11px;border-bottom:1px solid #f1f5f9;
  font-size:12.5px;vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
tbody tr.data-row:hover{background:#f8fafc !important}
.owner-cell{font-weight:700;color:#0f172a;white-space:nowrap;
  cursor:pointer;background:none;border:none;font-family:inherit;
  font-size:12.5px;padding:0;text-align:left}
.owner-cell:hover{color:#2563eb;text-decoration:underline}
td.c{text-align:center;font-family:'JetBrains Mono',monospace;font-size:12.5px;color:#0f172a}
td.c.zero{color:#0f172a;font-weight:500}
td.c.bold{font-weight:700}
.total-row td{font-weight:900 !important;
  background:linear-gradient(180deg,#1e293b,#0f172a) !important;
  color:#ffffff !important;
  border-top:3px solid #3b82f6;border-bottom:none;font-size:14px;
  padding:14px 14px;text-transform:uppercase;letter-spacing:.05em}
.total-row td.c{color:#ffffff !important;font-family:'JetBrains Mono',monospace;
  font-weight:900;font-size:14px}
.total-row .ov-badge{background:#dc2626 !important;color:#ffffff !important;
  font-weight:900;font-size:13px;padding:3px 11px;border:1px solid #ef4444}
.total-row .bar-track{background:rgba(255,255,255,.15) !important;
  border:1px solid rgba(255,255,255,.25) !important}
.total-row .dbar{background:rgba(255,255,255,.12) !important;
  border-color:rgba(255,255,255,.25) !important}
.total-row .dbar-lbl{color:#ffffff !important;text-shadow:0 1px 2px rgba(0,0,0,.3)}
.total-row .owner-cell{color:#ffffff !important;font-weight:900}

/* ── bidirectional center-baseline progress bar ─────────────── */
.dbar{position:relative;height:24px;border-radius:5px;
  background:#f8fafc;border:1px solid #e2e8f0;overflow:hidden;min-width:140px}
.dbar::after{content:'';position:absolute;left:50%;top:0;bottom:0;
  width:2px;background:#94a3b8;transform:translateX(-1px);z-index:1}
.dbar-fill{position:absolute;top:0;bottom:0;z-index:0}
.dbar-pos{left:50%;background:linear-gradient(90deg,#86efac,#10b981)}
.dbar-neg{right:50%;background:linear-gradient(270deg,#fca5a5,#dc2626)}
.dbar-stuck{left:0;right:50%;background:linear-gradient(270deg,#fca5a5,#ef4444)}
.dbar-done{background:transparent}
.dbar-lbl{position:absolute;inset:0;display:flex;align-items:center;
  justify-content:center;font-family:'JetBrains Mono',monospace;font-size:13.5px;
  font-weight:800;z-index:2;letter-spacing:.02em;
  text-shadow:0 1px 2px rgba(255,255,255,.9), 0 0 4px rgba(255,255,255,.6)}
.dbar-lbl.pos{color:#065f46}
.dbar-lbl.neg{color:#991b1b}
.dbar-lbl.zero{color:#334155}.dbar-lbl.new{color:#92400e}

/* ── row colour ──────────────────────────────────────────────── */
tr.row-green{background:#f0fdf4 !important}
tr.row-red  {background:#fff5f5 !important}

/* ── pct cell ────────────────────────────────────────────────── */
.pct-wrap{display:flex;align-items:center;gap:6px;min-width:90px}
.pct-val{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;min-width:36px}
.pct-green{color:#059669}.pct-red{color:#dc2626}.pct-neutral{color:#334155}.pct-blue{color:#2563eb}
.bar-track{flex:1;height:7px;border-radius:4px;background:#e2e8f0;overflow:hidden;min-width:40px}
.bar-fill{height:100%;border-radius:4px}
.bar-green{background:linear-gradient(90deg,#34d399,#059669)}
.bar-red  {background:linear-gradient(90deg,#f87171,#dc2626)}
.bar-blue {background:linear-gradient(90deg,#93c5fd,#2563eb)}
.bar-brown{background:linear-gradient(90deg,#d4a574,#92400e)}

/* ── overdue / delta badges ──────────────────────────────────── */
.ov-badge{display:inline-flex;align-items:center;gap:2px;
  background:#fee2e2;color:#991b1b;
  font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:800;
  padding:2px 9px;border-radius:5px}
.ov-zero{color:#0f172a;font-family:'JetBrains Mono',monospace;font-size:12.5px;font-weight:500}
.delta{display:inline-block;font-family:'JetBrains Mono',monospace;
  font-weight:700;font-size:11px;padding:2px 7px;
  border-radius:12px;white-space:nowrap}
.d-up     {background:#dcfce7;color:#166534;border:1px solid #bbf7d0}
.d-down   {background:#fee2e2;color:#991b1b;border:1px solid #fecaca}
.d-flat-ok{background:#f1f5f9;color:#64748b;border:1px solid #e2e8f0}
.d-flat-bad{background:#fee2e2;color:#991b1b;border:1px solid #fecaca}
.d-new    {background:#fef9c3;color:#92400e;border:1px solid #fde68a}

/* ── history range btns ──────────────────────────────────────── */
.range-wrap{display:flex;gap:4px;margin-left:auto}
.rbtn{background:#fff;border:1.5px solid #e2e8f0;border-radius:7px;
  color:#64748b;font-size:11px;font-weight:600;padding:4px 11px;
  cursor:pointer;transition:all .15s;font-family:inherit}
.rbtn.active,.rbtn:hover{background:#2563eb;color:#fff;border-color:#2563eb}

/* ── empty ───────────────────────────────────────────────────── */
.empty{padding:24px;text-align:center;color:#94a3b8;font-size:12.5px}

/* ── toast ───────────────────────────────────────────────────── */
#toast{position:fixed;bottom:18px;right:18px;z-index:600;
  background:#1e293b;color:#f8fafc;border-radius:10px;
  padding:10px 16px;font-size:12.5px;opacity:0;
  transition:opacity .25s;pointer-events:none;max-width:300px}
#toast.show{opacity:1}

/* ── laser pointer (presentation mode) ───────────────────────── */
#laser-dot{position:fixed;top:0;left:0;width:14px;height:14px;margin:-7px 0 0 -7px;
  z-index:100000;pointer-events:none;display:none;border-radius:50%;
  background:radial-gradient(circle at 50% 50%,#fff 0%,#ff6a6a 32%,#e11d1d 60%,rgba(225,29,29,0) 72%);
  box-shadow:0 0 5px 2px rgba(255,70,70,.8),0 0 13px 4px rgba(225,29,29,.45);
  will-change:transform}
#laser-dot::after{content:"";position:absolute;top:50%;left:50%;width:4px;height:4px;
  margin:-2px 0 0 -2px;border-radius:50%;background:#fff;
  box-shadow:0 0 4px 1px rgba(255,255,255,.95)}
/* click ripple — emphasises whatever you're pointing at */
#laser-ring{position:fixed;top:0;left:0;width:22px;height:22px;margin:-11px 0 0 -11px;
  z-index:99999;pointer-events:none;border-radius:50%;border:2px solid rgba(225,29,29,.75);
  opacity:0;display:none;will-change:transform}
body.laser-on #laser-ring{display:block}
#laser-ring.pulse{animation:laserPulse .55s ease-out}
@keyframes laserPulse{from{opacity:.85;transform:scale(.5)}to{opacity:0;transform:scale(3.4)}}
body.laser-on{cursor:none}
body.laser-on #laser-dot{display:block}

/* ── person Jira-links modal ─────────────────────────────────── */
#person-modal .modal{max-width:720px}
.pm-head{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.pm-name{font-size:18px;font-weight:800;letter-spacing:-.02em;color:#0f172a}
.pm-sub{font-size:11.5px;color:#64748b;font-family:'JetBrains Mono',monospace}
.pm-group{margin-bottom:14px}
.pm-group-hdr{display:flex;align-items:center;gap:8px;font-size:11px;font-weight:800;
  text-transform:uppercase;letter-spacing:.1em;color:#475569;margin-bottom:6px}
.pm-group.overdue .pm-group-hdr{color:#991b1b}
.pm-count{font-family:'JetBrains Mono',monospace;background:#f1f5f9;color:#334155;
  padding:1px 7px;border-radius:5px;font-size:11px;font-weight:700}
.pm-group.overdue .pm-count{background:#fee2e2;color:#991b1b}
.pm-list{display:flex;flex-direction:column;gap:4px}
.pm-row{display:flex;align-items:center;gap:10px;padding:7px 11px;
  background:#fff;border:1px solid #e8eef5;border-radius:8px;
  text-decoration:none;color:#0f172a;transition:all .12s}
.pm-row:hover{border-color:#3b82f6;background:#f8fafc}
.pm-group.overdue .pm-row{border-left:3px solid #dc2626}
.pm-key{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;
  color:#2563eb;flex-shrink:0;min-width:90px}
.pm-summary{flex:1;font-size:12.5px;color:#334155;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.pm-status{font-size:10.5px;font-weight:700;color:#64748b;
  background:#f1f5f9;padding:2px 7px;border-radius:4px;flex-shrink:0;
  border:1px solid #e2e8f0;text-transform:capitalize}
/* Status palette — Done=light green, In Progress=blue, WFA=blue,
   On Hold=yellow, Open=white. Matched by lowercased status name. */
.pm-status.st-done{background:#dcfce7;color:#166534;border-color:#bbf7d0}
.pm-status.st-progress{background:#dbeafe;color:#1e40af;border-color:#bfdbfe}
.pm-status.st-wait{background:#dbeafe;color:#1e40af;border-color:#bfdbfe}
.pm-status.st-hold{background:#fef9c3;color:#854d0e;border-color:#fde68a}
.pm-status.st-open{background:#ffffff;color:#334155;border-color:#cbd5e1}
.pm-changed{font-family:'JetBrains Mono',monospace;font-size:10.5px;
  color:#64748b;flex-shrink:0;white-space:nowrap}
.pm-changed::before{content:'⏱ ';opacity:.7}
.pm-due{font-family:'JetBrains Mono',monospace;font-size:11px;color:#64748b;flex-shrink:0}
.pm-due.over{color:#dc2626;font-weight:700}

/* ── Activity Log modal ──────────────────────────────────────── */
#activity-modal .modal{max-width:980px;width:96vw}
.act-filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;
  padding:10px 12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px}
.act-filter-input{flex:1;min-width:160px;border:1.5px solid #e2e8f0;
  border-radius:7px;background:#fff;padding:7px 10px;font-size:12.5px;
  font-family:inherit;outline:none}
.act-filter-input:focus{border-color:#3b82f6}
.act-filter-sel{border:1.5px solid #e2e8f0;border-radius:7px;background:#fff;
  padding:7px 10px;font-size:12.5px;font-family:inherit;outline:none;cursor:pointer}
.act-list{max-height:62vh;overflow-y:auto;border:1px solid #e2e8f0;border-radius:10px}
.act-row{display:grid;grid-template-columns:130px 130px 100px 1fr 110px;
  gap:14px;align-items:center;padding:11px 14px;border-bottom:1px solid #f1f5f9;
  font-size:12.5px}
.act-row:last-child{border-bottom:none}
.act-row:hover{background:#f8fafc}
.act-when{font-family:'JetBrains Mono',monospace;font-size:12.5px;color:#0f172a;
  font-weight:700;white-space:nowrap}
.act-author{font-weight:700;color:#0f172a;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}
.act-field{font-size:11px;font-weight:700;letter-spacing:.06em;
  text-transform:uppercase;padding:3px 8px;border-radius:4px;text-align:center}
.act-field.status   {background:#dbeafe;color:#1e40af}
.act-field.duedate  {background:#fee2e2;color:#991b1b}
.act-field.assignee {background:#fef3c7;color:#854d0e}
.act-field.priority {background:#ede9fe;color:#5b21b6}
.act-change{color:#334155;font-size:12.5px;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}
.act-from{color:#64748b;text-decoration:line-through}
.act-arrow{color:#94a3b8;margin:0 5px}
.act-to{color:#0f172a;font-weight:600}
.act-key{font-family:'JetBrains Mono',monospace;font-size:11.5px;font-weight:700;
  color:#1e40af;text-decoration:none}
.act-key:hover{text-decoration:underline}
.act-summary{color:#94a3b8;font-size:11px;margin-top:2px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.act-empty{padding:30px;text-align:center;color:#94a3b8;font-size:13px}
@media(max-width:760px){
  .act-row{grid-template-columns:1fr;gap:4px}
}

/* ── Breaking-news ticker ────────────────────────────────────── */
#ticker-bar{display:none;align-items:stretch;gap:0;margin-bottom:14px;
  border-radius:12px;overflow:hidden;
  border:1.5px solid #bbf7d0;background:#fff;
  box-shadow:0 4px 18px rgba(22,163,74,.14)}
#ticker-bar.show{display:flex}
.ticker-label{flex-shrink:0;display:flex;align-items:center;gap:7px;
  padding:0 14px;
  background:linear-gradient(135deg,#16a34a,#15803d);color:#fff;
  font-weight:800;font-size:11.5px;letter-spacing:.14em;
  text-transform:uppercase;white-space:nowrap;
  border-right:1.5px solid #bbf7d0;position:relative;overflow:hidden;z-index:2}
/* moving stroke / sheen sweeping across the label — subtle "live" effect */
.ticker-label::after{content:'';position:absolute;top:0;left:-60%;width:55%;height:100%;
  background:linear-gradient(100deg,transparent,rgba(255,255,255,.38),transparent);
  transform:skewX(-20deg);animation:tickerSheen 3.4s ease-in-out infinite;pointer-events:none}
@keyframes tickerSheen{0%{left:-60%}55%,100%{left:135%}}
.ticker-label .tdot{width:8px;height:8px;border-radius:50%;background:#fff;
  box-shadow:0 0 0 4px rgba(255,255,255,.25);animation:livePulse 1.4s infinite;position:relative;z-index:1}
.ticker-track{flex:1;overflow:hidden;position:relative;min-width:0;
  background:#f6fef9}
.ticker-track::before,.ticker-track::after{content:'';position:absolute;
  top:0;bottom:0;width:42px;z-index:1;pointer-events:none}
.ticker-track::before{left:0;background:linear-gradient(90deg,#f6fef9,transparent)}
.ticker-track::after {right:0;background:linear-gradient(270deg,#f6fef9,transparent)}
.ticker-strip{display:inline-flex;align-items:center;gap:18px;padding:9px 18px;
  animation:tickerScroll 50s linear infinite;white-space:nowrap}
.ticker-bar:hover .ticker-strip,
#ticker-bar:hover .ticker-strip{animation-play-state:paused}
@keyframes tickerScroll{
  from{transform:translateX(0)}
  to  {transform:translateX(-50%)}
}
.ticker-item{display:inline-flex;align-items:center;gap:7px;
  text-decoration:none;color:#0f172a;font-size:13px;
  padding:4px 10px;border-radius:7px;
  border:1px solid transparent;transition:background .15s,border-color .15s}
.ticker-item:hover{background:#fff;border-color:#bbf7d0}
.ticker-num{display:inline-flex;align-items:center;justify-content:center;
  min-width:18px;height:18px;padding:0 4px;border-radius:4px;
  background:#16a34a;color:#fff;font-size:10px;font-weight:800;
  letter-spacing:.02em;flex-shrink:0}
.ticker-key{font-family:'JetBrains Mono',monospace;font-size:11.5px;
  font-weight:700;color:#1e40af}
.ticker-arrow{color:#94a3b8;font-weight:700}
.ticker-status{font-size:11px;font-weight:700;padding:1px 7px;border-radius:4px;
  border:1px solid #e2e8f0;background:#f8fafc;color:#334155;text-transform:capitalize}
.ticker-status.st-done{background:#dcfce7;color:#166534;border-color:#bbf7d0}
.ticker-status.st-progress{background:#dbeafe;color:#1e40af;border-color:#bfdbfe}
.ticker-status.st-wait{background:#dbeafe;color:#1e40af;border-color:#bfdbfe}
.ticker-status.st-hold{background:#fef9c3;color:#854d0e;border-color:#fde68a}
.ticker-owner{font-weight:700;color:#475569;font-size:12px}
.ticker-time{font-family:'JetBrains Mono',monospace;font-size:11px;color:#64748b}
.ticker-sep{color:#86efac;font-weight:700}

/* ── LIVE freshness chip ─────────────────────────────────────── */
@keyframes livePulse {
  0%,100%{box-shadow:0 0 0 4px rgba(255,255,255,.25)}
  50%   {box-shadow:0 0 0 8px rgba(255,255,255,0)}
}
#live-chip.warm  {background:linear-gradient(135deg,#f59e0b,#d97706)!important;
                  box-shadow:0 2px 10px rgba(245,158,11,.35)!important}
#live-chip.stale {background:linear-gradient(135deg,#d97706,#92600a)!important;
                  box-shadow:0 2px 10px rgba(180,120,9,.35)!important}
#live-chip.refreshing #live-ago::after {content:' · refreshing…';opacity:.9}
/* While live data is being pulled from Jira, turn the LIVE chip RED. */
#live-chip.loading {background:linear-gradient(135deg,#10b981,#059669)!important;
                    box-shadow:0 2px 10px rgba(16,185,129,.4)!important}

/* ── footer ──────────────────────────────────────────────────── */
footer{text-align:center;font-size:11px;color:#94a3b8;margin-top:6px;
  font-family:'JetBrains Mono',monospace}

/* ── Mobile: tables fit the screen by default; pinch-zoom for detail ──
   Wide tables would be clipped by the card (overflow:hidden), hiding
   columns on phones. Wrap each table region in a scroller as a safety
   net, but the goal on phones is that the WHOLE table fits the viewport
   width by default — users pinch-zoom (allowed by the viewport meta,
   works in Samsung Internet / Chrome / Safari) to read fine detail. */
#tbl-tw, #tbl-lw, #tbl-ch, #tbl-hist {
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;   /* momentum scroll if it ever overflows */
}
/* Give weekly tables a readable minimum on tablets/desktop. */
.three-col table { min-width: 680px; }

@media(max-width:600px){.bar-track{display:none}}
@media(max-width:600px){
  .topbar-right{justify-content:flex-start}
  .stats{grid-template-columns:repeat(3,1fr)}
  .wrap{padding:0 8px}
  /* Stack the card header vertically so the date and the Copy/PC/Mobile/Export
     buttons get the full row width and wrap instead of being pushed off-screen. */
  .col-hdr{flex-direction:column;align-items:stretch;gap:8px;padding:12px 14px}
  .col-hdr-date{font-size:18px;text-align:left;flex:none;min-width:0}
  .col-hdr-actions{width:100%;justify-content:flex-start}
  .col-hdr-btn{padding:6px 9px}
  /* Same treatment for the Analytics Dashboard header (Copy/PC/Mobile/Collapse). */
  .analytics-header{flex-direction:column;align-items:stretch;gap:8px}
  .analytics-actions{flex-wrap:wrap}

  /* Fit the whole table on a phone screen by default — pinch-zoom for detail.
     The 9-column snapshot tables overflowed because (a) a fixed min-width and
     (b) the trailing "Owner's Progress" bar column kept a 160px-wide cell even
     though the bar itself is already hidden on mobile. So: drop the min-width,
     collapse that dead bar column, and shrink cell padding/fonts so the eight
     informational columns all fit at a glance. */
  table { min-width: 0; }
  /* Fixed layout makes the columns share the screen width instead of growing
     to fit content; Owner gets a wider share, the 7 numeric columns split the
     rest. Everything wraps so nothing clips. */
  .snap-table { min-width: 0; width: 100%; table-layout: fixed; }
  .snap-table th:last-child,
  .snap-table td:last-child { display: none; }            /* decorative bar — already hidden */
  .snap-table th, .snap-table td { padding-left: 4px; padding-right: 4px; font-size: 10px;
                                   white-space: normal; word-break: break-word; overflow-wrap: anywhere; }
  .snap-table th:first-child, .snap-table td:first-child { width: 26%; }
  .snap-table .owner-cell { font-size: 10px; white-space: normal; text-align: left; display: inline; padding: 0; }
  /* swap long headers for short labels on phones */
  .snap-table .lbl-full { display: none; }
  .snap-table .lbl-abbr { display: inline; }
}
</style>
</head>
<body>

<!-- Laser pointer (presentation mode) -->
<div id="laser-dot" aria-hidden="true"></div>
<div id="laser-ring" aria-hidden="true"></div>

<!-- ═══════════════ Opening splash (plays after unlock) ════════════════════ -->
<div id="intro-splash" aria-hidden="true">
<style>
#intro-splash{position:fixed;inset:0;z-index:9999;display:none;overflow:hidden;pointer-events:none}
#intro-splash.on{display:block}
#intro-splash .sp-half{position:absolute;left:0;width:100%;height:50.5%;background:linear-gradient(180deg,#FAF9F5,#F3F0E8)}
#intro-splash .sp-top{top:0}
#intro-splash .sp-bot{bottom:0}
#intro-splash.on .sp-top{animation:spTop .7s 2.75s cubic-bezier(.65,0,.35,1) forwards}
#intro-splash.on .sp-bot{animation:spBot .7s 2.75s cubic-bezier(.65,0,.35,1) forwards}
@keyframes spTop{to{transform:translateY(-102%)}}
@keyframes spBot{to{transform:translateY(102%)}}
#intro-splash .sp-center{position:absolute;inset:0;display:grid;place-items:center;text-align:center}
#intro-splash.on .sp-center{animation:spFade .45s 2.5s ease forwards}
@keyframes spFade{to{opacity:0;transform:scale(.96)}}
#intro-splash .sp-badges{display:flex;align-items:center;justify-content:center;gap:26px;position:relative}
#intro-splash .sp-fib,#intro-splash .sp-cbi{opacity:0;position:relative;overflow:hidden}
#intro-splash .sp-fib{width:96px;height:96px;border-radius:24px;background:linear-gradient(135deg,#4F9D8B,#2E6557);display:grid;place-items:center;font:800 30px/1 system-ui,'Segoe UI',sans-serif;color:#fff;letter-spacing:.5px;box-shadow:0 18px 40px -14px rgba(46,101,87,.55)}
#intro-splash .sp-cbi{width:96px;height:96px;border-radius:50%;background:radial-gradient(circle at 32% 28%,#23695A,#143E34);display:grid;place-items:center;color:#E8C766;box-shadow:0 18px 40px -14px rgba(20,62,52,.6);border:3px solid #C9A227}
#intro-splash .sp-cbi b{font:800 26px/1 Georgia,serif;letter-spacing:1px;display:block}
#intro-splash .sp-cbi i{display:block;font:600 6.5px/1.4 system-ui,sans-serif;letter-spacing:.12em;font-style:normal;opacity:.9;margin-top:3px}
#intro-splash.on .sp-fib{animation:spFromL .85s .15s cubic-bezier(.18,1.2,.3,1) forwards}
#intro-splash.on .sp-cbi{animation:spFromR .85s .15s cubic-bezier(.18,1.2,.3,1) forwards}
@keyframes spFromL{from{opacity:0;transform:translateX(-46vw) rotate(-28deg) scale(.7)}60%{opacity:1}to{opacity:1;transform:none}}
@keyframes spFromR{from{opacity:0;transform:translateX(46vw) rotate(28deg) scale(.7)}60%{opacity:1}to{opacity:1;transform:none}}
#intro-splash .sp-fib::after,#intro-splash .sp-cbi::after{content:'';position:absolute;inset:0;transform:translateX(-130%) skewX(-18deg);background:linear-gradient(90deg,transparent,rgba(255,255,255,.55),transparent)}
#intro-splash.on .sp-fib::after{animation:spShine .8s 1.15s ease forwards}
#intro-splash.on .sp-cbi::after{animation:spShine .8s 1.3s ease forwards}
@keyframes spShine{to{transform:translateX(130%) skewX(-18deg)}}
#intro-splash .sp-link{width:34px;height:34px;border-radius:50%;background:#fff;border:2px solid #C9A227;display:grid;place-items:center;color:#8a6d1c;font:700 15px/1 system-ui,sans-serif;opacity:0;transform:scale(.4)}
#intro-splash.on .sp-link{animation:spPop .5s 1s cubic-bezier(.18,1.5,.4,1) forwards}
@keyframes spPop{to{opacity:1;transform:scale(1)}}
#intro-splash .sp-ring{position:absolute;left:50%;top:50%;width:130px;height:130px;margin:-65px 0 0 -65px;border-radius:50%;border:2px solid rgba(79,157,139,.5);opacity:0}
#intro-splash.on .sp-ring{animation:spRing 1s 1.05s ease-out forwards}
@keyframes spRing{from{opacity:.9;transform:scale(.6)}to{opacity:0;transform:scale(2.6)}}
#intro-splash .sp-title{margin-top:30px;opacity:0}
#intro-splash .sp-title h1{margin:0;font:800 clamp(26px,4vw,40px)/1.15 system-ui,'Segoe UI',sans-serif;color:#3D3929}
#intro-splash .sp-title h1 span{color:#3A7D6E}
#intro-splash .sp-title p{margin:8px 0 0;font:600 13px/1 system-ui,sans-serif;letter-spacing:.22em;text-transform:uppercase;color:#8a8676}
#intro-splash.on .sp-title{animation:spUp .7s 1.45s cubic-bezier(.22,1,.36,1) forwards}
@keyframes spUp{from{opacity:0;transform:translateY(26px)}to{opacity:1;transform:none}}
#intro-splash .sp-line{height:3px;width:0;margin:14px auto 0;border-radius:3px;background:linear-gradient(90deg,#C9A227,#4F9D8B)}
#intro-splash.on .sp-line{animation:spLine .7s 1.85s cubic-bezier(.22,1,.36,1) forwards}
@keyframes spLine{to{width:180px}}
#intro-splash .sp-f{position:absolute;font:700 13px/1 system-ui,sans-serif;color:#3A7D6E;background:#fff;border:1.5px solid #C3E0D8;border-radius:12px;padding:8px 12px;box-shadow:0 12px 26px -12px rgba(58,125,110,.5);opacity:0}
#intro-splash.on .sp-f{animation:spF .7s cubic-bezier(.22,1,.36,1) forwards,spFOut .4s 2.25s ease forwards}
#intro-splash .sp-f1{left:12%;top:24%;animation-delay:1.55s,2.25s!important}
#intro-splash .sp-f2{right:13%;top:28%;animation-delay:1.65s,2.25s!important}
#intro-splash .sp-f3{left:16%;bottom:26%;animation-delay:1.75s,2.25s!important}
#intro-splash .sp-f4{right:17%;bottom:23%;animation-delay:1.85s,2.25s!important}
@keyframes spF{from{opacity:0;transform:translateY(18px) scale(.85)}to{opacity:1;transform:none}}
@keyframes spFOut{to{opacity:0;transform:translateY(-10px) scale(.9)}}
@media (max-width:760px){#intro-splash .sp-f{display:none}}
</style>
<div class="sp-half sp-top"></div>
<div class="sp-half sp-bot"></div>
<div class="sp-center">
  <div>
    <div class="sp-badges">
      <div class="sp-ring"></div>
      <div class="sp-fib">FIB</div>
      <div class="sp-link">&#10003;</div>
      <div class="sp-cbi"><div><b>CBI</b><i>CENTRAL BANK<br>OF IRAQ</i></div></div>
    </div>
    <div class="sp-title">
      <h1><span>Weekly</span> Progress Report</h1>
      <p>First Iraq Bank &middot; PMO</p>
      <div class="sp-line"></div>
    </div>
  </div>
</div>
<div class="sp-f sp-f1">&#10003; Tasks done</div>
<div class="sp-f sp-f2">&#9646;&#9646;&#9646; Progress</div>
<div class="sp-f sp-f3">&#9201; This week</div>
<div class="sp-f sp-f4">100%</div>
</div>

<!-- ═══════════════ Password Gate ══════════════════════════════════════════ -->
<div id="pw-overlay">
  <div class="pw-card">
    <div class="pw-brand">FIB</div>
    <div class="pw-kicker">First Iraq Bank · PMO</div>
    <h2>FIBTMP Progress Report</h2>
    <p>Enter the site password to open the live report.</p>
    <div class="pw-field">
      <input id="pw-inp" class="inp" type="password" placeholder="Site password"
             autocomplete="current-password" onkeydown="if(event.key==='Enter')checkPw()">
      <button type="button" class="pw-eye"
              onclick="var i=document.getElementById('pw-inp');var s=i.type==='password';i.type=s?'text':'password';this.textContent=s?'Hide':'Show';i.focus()">Show</button>
    </div>
    <button class="btn-primary" onclick="checkPw()">Unlock report →</button>
    <div class="err-msg" id="pw-err"></div>
    <div class="pw-foot">Encrypted end-to-end — nothing is readable without the password.<br>Authorized staff only.</div>
  </div>
</div>

<!-- ═══════════════ Export Modal ═══════════════════════════════════════════ -->
<div class="modal-overlay hidden" id="export-modal">
  <div class="modal">
    <h3>📷 Export Image</h3>

    <div class="modal-section">
      <div class="modal-section-label">Sections to include</div>
      <div class="check-grid" id="exp-sections">
        <label class="check-item on"><input type="checkbox" checked data-sec="tw"> This Week</label>
        <label class="check-item on"><input type="checkbox" checked data-sec="lw"> Last Week</label>
        <label class="check-item on"><input type="checkbox" checked data-sec="ch"> Changes</label>
        <label class="check-item"><input type="checkbox" data-sec="dash"> Dashboard (Donut + RAG + KPIs + Escalation)</label>
        <label class="check-item" id="exp-hist-lbl"><input type="checkbox" data-sec="hist"> History (specific week)</label>
      </div>
      <div id="exp-hist-sel-row" style="margin-top:10px;display:none">
        <div class="modal-section-label">Which week</div>
        <select class="week-sel" id="exp-hist-week"></select>
      </div>
    </div>

    <div class="modal-section">
      <div class="modal-section-label">Hide people from export <span style="font-weight:400;text-transform:none;letter-spacing:0;color:#94a3b8">(click to toggle)</span></div>
      <div class="vis-grid" id="exp-people-btns"></div>
      <button class="save-permanent-btn" id="save-hidden-btn" onclick="saveHiddenList()">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
        Save permanently (everyone)
      </button>
      <div class="persist-note">
        Saves the current hidden list to the repo so it persists across browsers
        and is shared with everyone who opens the site.
      </div>
    </div>

    <div class="modal-actions">
      <button class="btn-modal ghost" onclick="closeModal('export-modal')">Cancel</button>
      <button class="btn-modal blue" onclick="doExportImage(false)" style="margin-right:4px">Save Image on PC</button>
      <button class="btn-modal blue" onclick="doExportImage(true)">Save Image on Mobile</button>
    </div>
  </div>
</div>

<!-- ═══════════════ Epic Excel Modal (choose start date) ════════════════════ -->
<div class="modal-overlay hidden" id="epic-excel-modal" onclick="if(event.target===this)closeModal('epic-excel-modal')">
  <div class="modal" style="max-width:420px">
    <h3>📊 Export Epic Excel</h3>
    <div class="modal-section">
      <div class="modal-section-label">From date</div>
      <input type="date" id="epic-excel-start" style="width:100%;padding:8px 10px;border-radius:8px;border:1px solid #cbd5e1;font-size:14px">
      <div class="persist-note" style="margin-top:8px">
        One status column per day, from this date through <b id="epic-excel-today-label"></b>
        (today's column is always live). Remembers your last pick for next time.
      </div>
    </div>
    <div class="modal-actions">
      <button class="btn-modal ghost" onclick="closeModal('epic-excel-modal')">Cancel</button>
      <button class="btn-modal blue" onclick="confirmEpicExcelExport()">Download</button>
    </div>
  </div>
</div>

<!-- ═══════════════ Compare Excel Modal ════════════════════════════════════ -->
<div class="modal-overlay hidden" id="compare-modal">
  <div class="modal">
    <h3>📊 Compare with Excel</h3>
    <p style="font-size:12.5px;color:#64748b;margin-bottom:14px">
      Upload your Excel file. The tool reads the first sheet and matches
      owner names to live Jira data. This is <strong>temporary</strong> — nothing is saved to history.
    </p>
    <input type="file" accept=".xlsx,.xls" id="cmp-file"
           style="display:none" onchange="loadCompareExcel(this)">
    <button class="btn-modal blue" onclick="document.getElementById('cmp-file').click()">
      📂 Choose Excel file
    </button>
    <div id="cmp-wrap"></div>
    <div class="modal-actions">
      <button class="btn-modal ghost" onclick="closeModal('compare-modal')">Close</button>
    </div>
  </div>
</div>

<!-- ═══════════════ Compare Periods Modal ══════════════════════════════════ -->
<div class="modal-overlay hidden" id="compare-mode-modal">
  <div class="modal" style="max-width:900px;width:96vw">
    <h3>🔍 Compare Two Snapshots</h3>
    <p style="font-size:12.5px;color:#64748b;margin-bottom:14px">
      Select any two snapshots from history to compare side-by-side. Useful for PMO
      reviews — pick "start of month" vs "now" or any two specific weeks.
    </p>
    <div style="display:flex;gap:10px;align-items:end;flex-wrap:wrap;margin-bottom:14px">
      <div style="flex:1;min-width:160px">
        <div class="modal-section-label">Snapshot A (baseline)</div>
        <select class="week-sel" id="cmp-a" style="width:100%" onchange="renderPeriodCompare()"></select>
      </div>
      <div style="font-size:20px;color:#94a3b8;padding:6px">→</div>
      <div style="flex:1;min-width:160px">
        <div class="modal-section-label">Snapshot B (compared)</div>
        <select class="week-sel" id="cmp-b" style="width:100%" onchange="renderPeriodCompare()"></select>
      </div>
    </div>
    <div id="cmp-mode-result" style="overflow-x:auto;max-height:60vh"></div>
    <div class="modal-actions">
      <button class="btn-modal ghost" onclick="closeModal('compare-mode-modal')">Close</button>
    </div>
  </div>
</div>

<!-- ═══════════════ Activity Log Modal ═════════════════════════════════════ -->
<div class="modal-overlay hidden" id="activity-modal" onclick="if(event.target===this)closeModal('activity-modal')">
  <div class="modal">
    <div class="pm-head">
      <div style="flex:1;min-width:0">
        <div class="pm-name" style="color:#0369a1">🕒 Activity Log</div>
        <div class="pm-sub" id="act-sub">Last 24 hours · who changed what</div>
      </div>
      <button class="btn-modal ghost" onclick="closeModal('activity-modal')">Close</button>
    </div>
    <div class="act-filters">
      <input class="act-filter-input" id="act-search" type="search" placeholder="Filter by person, task key, or text…" oninput="_renderActivityList()">
      <select class="act-filter-sel" id="act-field" onchange="_renderActivityList()">
        <option value="">All changes</option>
        <option value="status">Status only</option>
        <option value="duedate">Due date only</option>
        <option value="assignee">Assignee only</option>
        <option value="priority">Priority only</option>
      </select>
      <select class="act-filter-sel" id="act-range" onchange="_renderActivityList()">
        <option value="1" selected>Last 24 hours</option>
        <option value="7">Last 7 days</option>
        <option value="14">Last 14 days</option>
        <option value="30">Last 30 days</option>
      </select>
    </div>
    <div class="act-list" id="act-list"></div>
  </div>
</div>

<!-- ═══════════════ Overdue Tasks Modal ════════════════════════════════════ -->
<div class="modal-overlay hidden" id="overdue-modal" onclick="if(event.target===this)closeModal('overdue-modal')">
  <div class="modal" style="max-width:880px">
    <div class="pm-head">
      <div style="flex:1;min-width:0">
        <div class="pm-name" id="ov-title" style="color:#991b1b">⚠ Overdue tasks</div>
        <div class="pm-sub" id="ov-sub"></div>
      </div>
      <button class="btn-modal ghost" onclick="closeModal('overdue-modal')">Close</button>
    </div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
      <button class="col-hdr-btn" onclick="openCommentModal()" title="Comment on overdue issues in Jira — pick by type, @mention the owner, CC people from the sheet"
              style="background:linear-gradient(135deg,#16a34a,#15803d);color:#fff;border-color:transparent">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
        💬 Comment in Jira
      </button>
      <button class="col-hdr-btn" onclick="copyOverdueRichHTML()" title="Copy formatted table with clickable Jira links — best for Outlook / Teams paste"
              style="background:linear-gradient(135deg,#3b82f6,#1d4ed8);color:#fff;border-color:transparent">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        Copy for Outlook (with links)
      </button>
      <button class="col-hdr-btn" onclick="copyOverdueImage()" title="Copy as PNG image to clipboard">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="15" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 18"/></svg>
        Copy as image
      </button>
      <button class="col-hdr-btn" onclick="exportOverdueExcel()" title="Download a colour-coded Excel file, grouped by owner"
              style="background:linear-gradient(135deg,#1d6f42,#14532d);color:#fff;border-color:transparent">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><rect x="2" y="2" width="20" height="20" rx="2" fill="white" opacity="0.9"/><path d="M8 7l2.5 5L8 17h2l1.5-3.5L13 17h2l-2.5-5L15 7h-2l-1.5 3.5L10 7H8z" fill="#1D6F42"/><rect x="15" y="7" width="4" height="1.5" fill="#1D6F42" rx="0.3"/><rect x="15" y="10.5" width="4" height="1.5" fill="#1D6F42" rx="0.3"/><rect x="15" y="14" width="4" height="1.5" fill="#1D6F42" rx="0.3"/></svg>
        Download Excel
      </button>
      <button class="col-hdr-btn" onclick="exportOverduePNG(false)" title="Download JPG to Windows/PC">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        PC
      </button>
      <button class="col-hdr-btn" onclick="exportOverduePNG(true)" title="Share to mobile / Save to Photos">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="2" x2="12" y2="15"/></svg>
        Mobile
      </button>
    </div>
    <div id="ov-body"></div>
  </div>
</div>

<!-- ═══════════════ Comment-on-Overdue Modal ═══════════════════════════════ -->
<div class="modal-overlay hidden" id="comment-modal" onclick="if(event.target===this)closeModal('comment-modal')">
  <div class="modal" style="max-width:760px">
    <div class="pm-head">
      <div style="flex:1;min-width:0">
        <div class="pm-name" style="color:#15803d">💬 Comment on overdue issues</div>
        <div class="pm-sub" id="cm-sub">Pick which issues to nudge — they get a real Jira comment with @owner mentioned.</div>
      </div>
      <button class="btn-modal ghost" onclick="closeModal('comment-modal')">Close</button>
    </div>

    <!-- Type filter: choose which issue types to include before commenting -->
    <div style="margin-bottom:10px">
      <div style="font-size:11px;font-weight:800;letter-spacing:.06em;color:#475569;text-transform:uppercase;margin-bottom:5px">Include issue types</div>
      <div id="cm-types" style="display:flex;gap:6px;flex-wrap:wrap"></div>
    </div>

    <!-- People filter: deselect a person to hide their tasks (e.g. don't nudge the CTO) -->
    <div style="margin-bottom:10px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px">
        <div style="font-size:11px;font-weight:800;letter-spacing:.06em;color:#475569;text-transform:uppercase">Include people</div>
        <div style="font-size:11.5px">
          <a href="#" onclick="cmSetPeople(true);return false" style="color:#2563eb;text-decoration:none">All</a> ·
          <a href="#" onclick="cmSetPeople(false);return false" style="color:#64748b;text-decoration:none">None</a>
        </div>
      </div>
      <div id="cm-people" style="display:flex;gap:6px;flex-wrap:wrap;max-height:96px;overflow:auto"></div>
    </div>

    <!-- Comment template -->
    <div style="margin-bottom:10px">
      <div style="font-size:11px;font-weight:800;letter-spacing:.06em;color:#475569;text-transform:uppercase;margin-bottom:5px">
        Comment body <span style="font-weight:600;text-transform:none;letter-spacing:0;color:#94a3b8">— @owner becomes a Jira mention, @cc becomes the CC people below</span>
      </div>
      <textarea id="cm-template" rows="3" style="width:100%;box-sizing:border-box;font-family:inherit;font-size:13px;padding:9px 11px;border:1px solid #cbd5e1;border-radius:8px;resize:vertical">@owner, {action}

CC: @cc</textarea>
    </div>

    <!-- CC people (from the sheet / saved recipients) -->
    <div style="margin-bottom:10px">
      <div style="font-size:11px;font-weight:800;letter-spacing:.06em;color:#475569;text-transform:uppercase;margin-bottom:5px">
        CC people <span style="font-weight:600;text-transform:none;letter-spacing:0;color:#94a3b8">— comma-separated emails; resolved to @mentions server-side</span>
      </div>
      <input id="cm-cc" type="text" placeholder="someone@fib.iq, another@fib.iq"
             style="width:100%;box-sizing:border-box;font-family:inherit;font-size:13px;padding:9px 11px;border:1px solid #cbd5e1;border-radius:8px">
    </div>

    <!-- Per-issue list with checkboxes (deselect to exclude) -->
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px">
      <div style="font-size:11px;font-weight:800;letter-spacing:.06em;color:#475569;text-transform:uppercase">Issues to comment on</div>
      <div style="font-size:11.5px">
        <a href="#" onclick="cmSetAll(true);return false" style="color:#2563eb;text-decoration:none">Select all</a> ·
        <a href="#" onclick="cmSetAll(false);return false" style="color:#64748b;text-decoration:none">None</a>
      </div>
    </div>
    <div id="cm-list" style="max-height:280px;overflow:auto;border:1px solid #e2e8f0;border-radius:8px"></div>

    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px;align-items:center">
      <span id="cm-status" style="font-size:12px;color:#64748b;margin-right:auto"></span>
      <button class="btn-modal ghost" onclick="closeModal('comment-modal')">Close</button>
      <button class="btn-modal ghost" id="cm-cancel-btn" onclick="cancelQueue()"
              title="Discard queued-but-not-yet-posted comments and stop any in-progress run"
              style="color:#b91c1c;border-color:#fecaca">Cancel queued batch</button>
      <button class="btn-modal" id="cm-post-btn" onclick="postComments()"
              style="background:linear-gradient(135deg,#16a34a,#15803d);color:#fff;border-color:transparent">
        Post <span id="cm-count">0</span> comment(s) to Jira
      </button>
    </div>
  </div>
</div>

<!-- ═══════════════ Team Directory (emails) Modal ══════════════════════════ -->
<div class="modal-overlay hidden" id="directory-modal" onclick="if(event.target===this)closeModal('directory-modal')">
  <div class="modal" style="max-width:720px">
    <div class="pm-head">
      <div style="flex:1;min-width:0">
        <div class="pm-name" style="color:#0f766e">👥 Team directory</div>
        <div class="pm-sub" id="dir-sub">Everyone with assigned work. Jira hides most emails — fill the blanks; they're saved encrypted.</div>
      </div>
      <button class="btn-modal ghost" onclick="closeModal('directory-modal')">Close</button>
    </div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px">
      <button class="col-hdr-btn" onclick="copyAllEmails()" title="Copy every filled email, comma-separated"
              style="background:linear-gradient(135deg,#14b8a6,#0f766e);color:#fff;border-color:transparent">📋 Copy all emails</button>
      <button class="col-hdr-btn" id="dir-save-btn" onclick="saveDirectory()" title="Save the emails (encrypted)">💾 Save</button>
      <span id="dir-status" style="font-size:12px;color:#64748b;align-self:center"></span>
    </div>
    <div id="dir-body" style="max-height:60vh;overflow:auto"></div>
  </div>
</div>

<!-- ═══════════════ Person Jira Links Modal ════════════════════════════════ -->
<div class="modal-overlay hidden" id="person-modal" onclick="if(event.target===this)closeModal('person-modal')">
  <div class="modal">
    <div class="pm-head">
      <div style="flex:1;min-width:0">
        <div class="pm-name" id="pm-name">—</div>
        <div class="pm-sub" id="pm-sub"></div>
      </div>
      <button class="btn-modal ghost" id="pm-copy-btn" onclick="copyPersonTasks(this)" style="margin-right:6px" title="Copy formatted table with clickable Jira links — best for Outlook / Teams paste">📋 Copy</button>
      <button class="btn-modal ghost" id="pm-export-btn" onclick="exportPersonTasks(false)" style="margin-right:6px" title="Download to PC">PC</button>
      <button class="btn-modal ghost" id="pm-export-mobile-btn" onclick="exportPersonTasks(true)" style="margin-right:6px" title="Share to mobile">Mobile</button>
      <button class="btn-modal ghost" onclick="closeModal('person-modal')">Close</button>
    </div>
    <div id="pm-body"></div>
  </div>
</div>

<!-- ═══════════════ Send by Email Modal ════════════════════════════════════ -->
<div class="modal-overlay hidden" id="email-modal">
  <div class="modal" style="max-width:580px">
    <h3>📧 Send Report by Email</h3>
    <p style="font-size:12.5px;color:#64748b;margin-bottom:6px" id="email-attach-info">
      Sends the default full report PNG. Use the Export Image button if you
      want to email only specific sections (This Week, Changes, Dashboard, etc.).
    </p>
    <p style="font-size:12.5px;color:#64748b;margin-bottom:14px">
      Sent from autoaifib@gmail.com via Gmail SMTP · arrives in ~30–45 seconds.
    </p>

    <div class="modal-section">
      <div class="modal-section-label">Saved recipients <span style="font-weight:400;text-transform:none;letter-spacing:0;color:#94a3b8">(click to toggle on/off for this send)</span></div>
      <div class="vis-grid" id="email-saved-list"></div>
    </div>

    <div class="modal-section">
      <div class="modal-section-label">Add another address</div>
      <div style="display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin-top:4px">
        <input class="inp" id="email-new-inp" type="email" placeholder="name@example.com"
               style="flex:1;min-width:200px;font-size:13px;padding:8px 12px"
               onkeydown="if(event.key==='Enter')addEmailToSelection()">
        <button class="btn-modal ghost" onclick="addEmailToSelection()">+ Add (this send)</button>
        <button class="btn-modal blue" onclick="saveEmailToList()" title="Persist for everyone">+ Save to list</button>
      </div>
    </div>

    <div class="modal-section" id="email-selected-summary"
         style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px">
      <div class="modal-section-label" style="margin-bottom:4px">Will send to <span id="email-count">0</span> address(es)</div>
      <div id="email-selected-display" style="font-size:12.5px;color:#0f172a;font-family:'JetBrains Mono',monospace;word-break:break-all;line-height:1.6"></div>
    </div>

    <div class="modal-actions">
      <button class="btn-modal ghost" onclick="_PENDING_EMAIL_CANVAS=null;_PENDING_EMAIL_LABEL='';closeModal('email-modal')">Cancel</button>
      <button class="btn-modal blue" id="send-email-btn" onclick="sendEmailNow()">📧 Send Now</button>
    </div>
  </div>
</div>

<!-- ═══════════════ Main App ═══════════════════════════════════════════════ -->
<div id="app" style="display:none">
<div class="wrap">

  <!-- Typewriter brand text (motion graphic) — above the Breaking bar -->
  <div class="fib-type" aria-label="First Iraqi Bank" style="margin-bottom:10px">
    <span id="fib-type-out"></span><span class="fib-caret">&nbsp;</span>
  </div>

  <!-- Breaking-news ticker (recent task changes) — pinned to the very top -->
  <div id="ticker-bar">
    <div class="ticker-label" id="ticker-breaking">
      <span class="tdot"></span>
      <span>Breaking</span>
      <span id="ticker-count" style="background:rgba(255,255,255,.25);padding:1px 8px;border-radius:999px;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:800;margin-left:4px">0</span>
    </div>
    <div class="ticker-track"><div class="ticker-strip" id="ticker-strip"></div></div>
  </div>

  <!-- Top bar -->
  <div class="topbar">
    <!-- ── Brand block (left edge) ──────────────────────────────────────── -->
    <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
      <div>
        <div class="brand-title">FIBTMP Progress Report</div>
        <div class="brand-sub" id="hdr-date">—</div>
      </div>
    </div>
    <style>
      .fib-type{display:inline-flex;align-items:center;font-weight:800;
        font-size:clamp(15px,2.2vw,20px);letter-spacing:.02em;white-space:nowrap;
        background:linear-gradient(90deg,#0e9488,#14b8a6,#0e7c74);
        -webkit-background-clip:text;background-clip:text;color:transparent;
        font-family:'Inter',system-ui,sans-serif}
      .fib-caret{display:inline-block;width:2px;height:1.05em;margin-left:2px;
        background:#14b8a6;-webkit-text-fill-color:#14b8a6;border-radius:1px;
        animation:fibBlink 1s steps(1) infinite}
      @keyframes fibBlink{0%,50%{opacity:1}50.01%,100%{opacity:0}}
    </style>

    <!-- ── Right block: status row on top, action row below ─────────────── -->
    <div class="topbar-right" style="display:flex;flex-direction:column;align-items:flex-end;gap:8px">

      <!-- Row 1: status / info chips (smaller, lower visual weight) -->
      <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;justify-content:flex-end">
        <span class="chip" id="live-chip" title="Page auto-refreshes when new data arrives">
          <span class="live-dot"></span>
          <span style="font-weight:700">LIVE</span>
          <span id="live-ago" style="font-family:'JetBrains Mono',monospace;font-weight:600;font-size:11.5px">just now</span>
        </span>
        <span class="last-run-chip" oncontextmenu="return _baselineMenu(event)" title="Choose the baseline - right-click to pin a snapshot (admin password)" style="padding:5px 9px">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
          <span style="font-weight:700">Baseline:</span>
          <select id="baseline-sel-top" class="baseline-sel"
                  style="border:none;background:transparent;padding:2px 4px;font-weight:600;cursor:pointer;max-width:170px"
                  onchange="setBaseline(this.value); var s=document.getElementById('baseline-sel'); if(s) s.value=this.value"></select>
          <button onclick="editAutoDay(event)" title="Change the weekly 'Auto' baseline day (admin password required)"
                  style="border:none;background:transparent;cursor:pointer;padding:2px;margin-left:2px;color:#64748b;display:inline-flex;align-items:center">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
          </button>
        </span>
        <span class="hidden-indicator" id="hidden-indicator" style="display:none" title="People hidden from view across all users — click 'Export Image' to manage">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m1 1 22 22"/><path d="M10.7 6.3a10 10 0 0 1 11.3 5.7 9.8 9.8 0 0 1-3.4 4.7"/><path d="M6.1 6.1A10.4 10.4 0 0 0 2 12s3 8 10 8a9.8 9.8 0 0 0 4.6-1.1"/></svg>
          <span class="hi-count">0</span><span style="opacity:.85">&nbsp;hidden</span>
        </span>
        <span class="refresh-progress" id="refresh-progress">
          <svg class="spinner" width="12" height="12" viewBox="0 0 50 50"><circle cx="25" cy="25" r="20" fill="none" stroke="currentColor" stroke-width="6" stroke-linecap="round" stroke-dasharray="80 200"/></svg>
          <span id="refresh-progress-txt">Working…</span>
        </span>
      </div>

      <!-- Row 2: action buttons -->
      <div class="topbar-actions" style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;justify-content:flex-end">
        <!-- Quick-look buttons first (red Overdue is highest-priority alert) -->
        <button class="chip chip-lg ac-red" id="overdue-btn" onclick="openOverdueModal()" style="display:none" title="Show all overdue tasks with Jira links">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          Overdue <span id="overdue-count" style="background:#dc2626;color:#fff;padding:1px 7px;border-radius:999px;margin-left:2px;font-family:'JetBrains Mono',monospace">0</span>
        </button>
        <button class="chip chip-lg" onclick="openDirectoryModal()" title="Team directory — everyone's email in one place (copy all)">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
          Team Emails
        </button>
        <button class="chip chip-lg" onclick="openActivityModal()" title="See every recent change — who, what, when">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          Activity Log
        </button>
        <!-- Vertical divider -->
        <span style="width:1px;height:24px;background:#e2e8f0;margin:0 4px"></span>
        <!-- Output buttons -->
        <button class="chip chip-lg" onclick="openExportModal()" title="Export the dashboard as a PNG image">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="3" width="18" height="15" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 18"/></svg>
          Export Image
        </button>
        <button class="chip chip-lg primary" id="refresh-live-btn" onclick="refreshLive(this)" title="Pull the latest data straight from Jira and update this page now — no reload, no rebuild">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 12a9 9 0 0 0-9-9 9 9 0 0 0-6.36 2.64L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9 9 0 0 0 6.36-2.64L21 16"/><path d="M21 21v-5h-5"/></svg>
          <span class="rl-txt">Refresh Live</span>
        </button>
      <!-- "More" dropdown for everything else -->
      <div class="menu-dropdown">
        <button class="chip" onclick="toggleMoreMenu(event)" id="more-btn" title="More actions">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/></svg>
          More
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="margin-left:2px"><polyline points="6 9 12 15 18 9"/></svg>
        </button>
        <div class="menu-items" id="more-menu">
          <div class="menu-section-label">Snapshots</div>
          <button class="menu-item" onclick="saveSnapshotNow();closeMoreMenu()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
            <div class="menu-item-text"><div>Save Snapshot</div><div class="menu-item-sub">Pin today's data to history</div></div>
          </button>

          <div class="menu-section-label">Data</div>
          <button class="menu-item" onclick="exportExcel();closeMoreMenu()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><rect x="2" y="2" width="20" height="20" rx="2" fill="#1D6F42"/><path d="M8 7l2.5 5L8 17h2l1.5-3.5L13 17h2l-2.5-5L15 7h-2l-1.5 3.5L10 7H8z" fill="white"/><rect x="15" y="7" width="4" height="1.5" fill="white" rx="0.3"/><rect x="15" y="10.5" width="4" height="1.5" fill="white" rx="0.3"/><rect x="15" y="14" width="4" height="1.5" fill="white" rx="0.3"/></svg>
            <div class="menu-item-text"><div>Export Excel</div><div class="menu-item-sub">Multi-sheet .xlsx download</div></div>
          </button>
          <button class="menu-item" onclick="openEpicExcelModal();closeMoreMenu()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><rect x="2" y="2" width="20" height="20" rx="2" fill="#1D6F42"/><path d="M8 7l2.5 5L8 17h2l1.5-3.5L13 17h2l-2.5-5L15 7h-2l-1.5 3.5L10 7H8z" fill="white"/><rect x="15" y="7" width="4" height="1.5" fill="white" rx="0.3"/><rect x="15" y="10.5" width="4" height="1.5" fill="white" rx="0.3"/><rect x="15" y="14" width="4" height="1.5" fill="white" rx="0.3"/></svg>
            <div class="menu-item-text"><div>Export Epic Excel</div><div class="menu-item-sub">FIBTMP-489 · pick a start date, one column per day to today</div></div>
          </button>
          <button class="menu-item" onclick="exportExecutivePPTX();closeMoreMenu()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><rect x="2" y="2" width="20" height="20" rx="2" fill="#C43E1C"/><rect x="5" y="6" width="9" height="1.5" fill="white" rx="0.4"/><rect x="5" y="9.5" width="7" height="1.5" fill="white" rx="0.4"/><rect x="5" y="13" width="6" height="1.5" fill="white" rx="0.4"/><circle cx="17" cy="16" r="4" fill="white" opacity="0.15"/><path d="M14.5 14.5l5 3-5 3V14.5z" fill="white"/></svg>
            <div class="menu-item-text"><div>Executive Summary (PPTX)</div><div class="menu-item-sub">RAG status, KPIs, risks &amp; escalations — one deck, ready to present</div></div>
          </button>

          <div class="menu-section-label">Presentation</div>
          <button class="menu-item" id="laser-menu-item" onclick="toggleLaser();closeMoreMenu()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><circle cx="12" cy="12" r="8"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/></svg>
            <div class="menu-item-text"><div>Laser Pointer <span id="laser-state" style="font-weight:700;color:#dc2626"></span></div><div class="menu-item-sub">Press L to toggle · click to pulse</div></div>
          </button>

        </div>
      </div>

      <a class="chip" href="admin.html" onclick="return gateAdmin(event)" title="Admin panel (password required)">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>
        Admin
      </a>
      </div><!-- /Row 2 -->
    </div>
  </div>

  <!-- Stats -->
  <section class="stats" id="stats-row"></section>

  <!-- Analytics dashboard: donut + PMO panel -->
  <div class="analytics-card" id="analytics-card">
    <div class="analytics-header">
      <div class="analytics-title">📈 PMO Analytics Dashboard
        <span id="analytics-time" style="margin-left:14px;font-family:'JetBrains Mono',monospace;font-size:11.5px;font-weight:600;color:#64748b;letter-spacing:.04em"></span>
      </div>
      <div class="analytics-actions">
        <button class="chip" id="analytics-copy-btn" onclick="copyAnalyticsDashboard(this)" title="Copy dashboard image to clipboard (paste into Outlook / Teams / Slack)">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          <span id="analytics-copy-txt">Copy</span>
        </button>
        <button class="chip" onclick="exportDashboard(false)" title="Download dashboard PNG to Windows/PC">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          PC
        </button>
        <button class="chip" onclick="exportDashboard(true)" title="Share dashboard to mobile / Save to Photos">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="12" x2="12" y2="15"/></svg>
          Mobile
        </button>
        <button class="chip" id="analytics-toggle" onclick="toggleAnalytics()" title="Collapse / expand">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" id="analytics-chevron"><polyline points="18 15 12 9 6 15"/></svg>
          <span id="analytics-toggle-txt">Collapse</span>
        </button>
      </div>
    </div>
    <div class="analytics-grid" id="analytics-grid">
      <div class="analytics-donut">
        <div class="analytics-label">Task Status Distribution</div>
        <div id="donut-wrap"></div>
      </div>
      <div class="analytics-bars">
        <div class="analytics-label">PMO Health Dashboard</div>
        <div id="pmo-wrap"></div>
      </div>
    </div>
  </div>

  <!-- AI Analysis -->
  <div class="ai-card">
    <div class="ai-header">
      <span class="ai-tag">🤖 AI Analysis</span>
      <span class="ai-date" id="ai-date"></span>
    </div>
    <p class="ai-text" id="ai-text"></p>
  </div>

  <!-- Risk Alerts -->
  <div id="risk-section">
    <div class="risk-title">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      AI Risk Flags
    </div>
    <div class="risk-grid" id="risk-grid"></div>
  </div>

  <!-- Tab bar -->
  <div class="tab-bar">
    <button class="tab-btn active" onclick="showTab('weekly',this)">📋 Weekly</button>
    <button class="tab-btn" onclick="showTab('hist',this)">📅 History</button>
  </div>

  <div class="panel">

    <!-- Filter bar -->
    <div class="filter-bar">
      <div class="search-wrap">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        <input class="search-inp" id="name-filter" type="search" placeholder="Filter by name…"
               oninput="applyFilter(this.value)" onsearch="applyFilter(this.value)">
      </div>
      <span class="filter-count" id="filter-count"></span>
      <button class="clear-btn" id="clear-btn" onclick="clearFilter()" title="Show all members">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        Show all members
      </button>
      <!-- history range (hist tab only) -->
      <div class="range-wrap" id="range-wrap" style="display:none">
        <button class="rbtn" onclick="setRange(7,this)">7 Days</button>
        <button class="rbtn" onclick="setRange(14,this)">14 Days</button>
        <button class="rbtn" onclick="setRange(30,this)">30 Days</button>
        <button class="rbtn active" onclick="setRange(0,this)">All</button>
      </div>
    </div>

    <!-- Weekly tab: 3 columns -->
    <div id="tab-weekly">
      <div class="three-col">
        <div class="col-block">
          <div class="col-hdr">
            <div class="col-hdr-label">
              <span class="col-dot dot-blue"></span>
              <span class="col-hdr-title">This Week</span>
            </div>
            <div class="col-hdr-date" id="tw-date"></div>
            <div class="col-hdr-actions">
              <button class="col-hdr-btn" onclick="copyHistTable(this)" title="Copy this table as image">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                Copy
              </button>
              <button class="col-hdr-btn" onclick="exportHistTable(this,'this-week',false)" title="Download to PC">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                PC
              </button>
              <button class="col-hdr-btn" onclick="exportHistTable(this,'this-week',true)" title="Share to mobile">Mobile</button>
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="15" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 18"/></svg>
                Export
              </button>
            </div>
          </div>
          <div id="tbl-tw"></div>
        </div>
        <div class="col-block">
          <div class="col-hdr">
            <div class="col-hdr-label">
              <span class="col-dot dot-slate"></span>
              <span class="col-hdr-title">Last Week</span>
            </div>
            <div class="col-hdr-date" id="lw-date"></div>
            <div class="col-hdr-actions">
              <select id="baseline-sel" class="baseline-sel" title="Baseline" onchange="setBaseline(this.value)"></select>
              <button class="col-hdr-btn" onclick="copyHistTable(this)" title="Copy this table as image">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                Copy
              </button>
              <button class="col-hdr-btn" onclick="exportHistTable(this,'last-week',false)" title="Download to PC">PC</button>
              <button class="col-hdr-btn" onclick="exportHistTable(this,'last-week',true)" title="Share to mobile">Mobile</button>
            </div>
          </div>
          <div id="tbl-lw"></div>
        </div>
        <div class="col-block">
          <div class="col-hdr">
            <div class="col-hdr-label">
              <span class="col-dot dot-amber"></span>
              <span class="col-hdr-title">Changes</span>
            </div>
            <div class="col-hdr-date" id="ch-date" style="font-size:18px;color:#475569"></div>
            <div class="col-hdr-actions">
              <button class="col-hdr-btn" onclick="copyHistTable(this)" title="Copy this table as image">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                Copy
              </button>
              <button class="col-hdr-btn" onclick="exportHistTable(this,'changes',false)" title="Download to PC">PC</button>
              <button class="col-hdr-btn" onclick="exportHistTable(this,'changes',true)" title="Share to mobile">Mobile</button>
            </div>
          </div>
          <div id="tbl-ch"></div>
        </div>
      </div>
    </div>

    <!-- History tab -->
    <div id="tab-hist" style="display:none">
      <div style="overflow-x:auto" id="tbl-hist"></div>
    </div>

  </div>

  <footer>FIBTMP &nbsp;·&nbsp; © <span id="copy-year">2026</span> PMO Team</footer>
</div>
</div>



<div id="toast"></div>

<script>
// ── encrypted payload ──────────────────────────────────────────────────────
// Source contains only AES-GCM ciphertext. Decrypted in-memory after correct password.
const ENC_BLOB = __ENC_BLOB__;
let REPORT   = null;
let ANALYSIS = null;
let GH_PAT   = '';

// ── GitHub proxy (optional) ────────────────────────────────────────────────
// If a Worker URL is configured (meta gh-proxy), the GitHub PAT lives in the
// Worker, NOT in this page. We transparently route every api.github.com call
// through the Worker, authenticating with the site password (already in
// sessionStorage after login). No call site changes; no token in the page.
const GH_PROXY = (document.querySelector('meta[name=gh-proxy]')?.content || '').trim();
(function installGitHubProxy(){
  if (!GH_PROXY) return;                       // not configured → behave as before
  const _origFetch = window.fetch.bind(window);
  const GH = 'https://api.github.com';
  window.fetch = function(url, opts){
    opts = opts || {};
    if (typeof url === 'string' && url.startsWith(GH)) {
      const path = url.slice(GH.length);
      const pw   = sessionStorage.getItem('pw_cache') || '';
      const hdrs = {'Content-Type':'application/json', 'X-Proxy-Auth': pw};
      // Forward the comment password (set transiently by postComments) so the
      // Worker can enforce it server-side for comment operations.
      if (window.__COMMENT_PW) hdrs['X-Comment-Auth'] = window.__COMMENT_PW;
      return _origFetch(GH_PROXY, {
        method: 'POST',
        headers: hdrs,
        body: JSON.stringify({ path, method: (opts.method || 'GET'), ghBody: opts.body || null })
      });
    }
    return _origFetch(url, opts);
  };
})();

// ── LIVE DATA ───────────────────────────────────────────────────────────────
// Recompute the REPORT object in-browser from fresh Jira issues, so the
// dashboard can update WITHOUT a page reload or a GitHub rebuild. The Jira
// token never touches this page — issues are fetched through the Cloudflare
// Worker's read-only `action:"jira"` endpoint (worker/github-proxy.js), which
// holds the token as a secret. This block mirrors src/calculate.py exactly so
// the live numbers match what the weekly Python job would produce.
const _LIVE = {
  isDone(issue){
    const st = (issue.fields||{}).status || {};
    if ((st.name||'').trim().toLowerCase() === 'available') return true;
    return ((st.statusCategory||{}).key) === 'done';
  },
  statusName(issue){ return ((issue.fields||{}).status||{}).name || 'Unknown'; },
  excelCategory(issue){
    if (_LIVE.isDone(issue)) return 'Completed';
    const n = _LIVE.statusName(issue).toLowerCase();
    if (n.includes('progress')) return 'In Progress';
    if (n.includes('wait') || n.includes('approv')) return 'Waiting For Approval';
    return 'Open';
  },
  isOverdue(issue){
    if (_LIVE.isDone(issue)) return false;
    const due = (issue.fields||{}).duedate;
    if (!due) return false;
    const d = new Date(String(due).slice(0,10) + 'T00:00:00Z');
    return !isNaN(d) && Date.now() > d.getTime();
  },
  assigneeName(issue){
    const a = (issue.fields||{}).assignee;
    return (a && a.displayName) ? a.displayName : 'Unassigned';
  },
  extractEvents(issue, maxAgeDays=30){
    const cl = ((issue.changelog||{}).histories) || [];
    const cutoff = Date.now() - maxAgeDays*86400000;
    const interesting = new Set(['status','duedate','assignee','priority']);
    const out = [];
    for (const h of cl){
      const when = h.created;
      if (!when) continue;
      const t = new Date(when).getTime();
      if (isNaN(t) || t < cutoff) continue;
      const author = (h.author||{}).displayName || 'Unknown';
      for (const it of (h.items||[])){
        const field = (it.field||'').toLowerCase();
        if (!interesting.has(field)) continue;
        out.push({when, author, field, from: it.fromString||'', to: it.toString||''});
      }
    }
    out.sort((a,b)=> a.when < b.when ? 1 : a.when > b.when ? -1 : 0);
    return out.slice(0,20);
  },
  issueRecord(issue){
    const f = issue.fields||{};
    const events = _LIVE.extractEvents(issue);
    const lastStatus = events.find(e=>e.field==='status') || null;
    const changed = lastStatus ? lastStatus.when : (f.statuscategorychangedate || f.updated);
    const assignee = f.assignee||{};
    const issuetype = f.issuetype||{};
    return {
      key: issue.key||'',
      summary: (f.summary||'').slice(0,200),
      status: _LIVE.statusName(issue),
      status_from: lastStatus ? lastStatus.from : null,
      category: _LIVE.excelCategory(issue),
      due: f.duedate,
      overdue: _LIVE.isOverdue(issue),
      changed, events,
      type: issuetype.name||'',
      is_subtask: !!issuetype.subtask,
      assignee_id: assignee.accountId||'',
      assignee_email: assignee.emailAddress||'',
    };
  },
  computeRates(issues, hiddenSet){
    const hidden = hiddenSet || new Set();
    const counts = {};
    for (const issue of issues){
      const name = _LIVE.assigneeName(issue);
      const cat  = _LIVE.excelCategory(issue);
      const sname = _LIVE.statusName(issue);
      if (!counts[name]) counts[name] = {total:0,completed:0,open:0,in_progress:0,waiting_for_approval:0,overdue:0,statuses:{},issues:[]};
      const c = counts[name];
      c.issues.push(_LIVE.issueRecord(issue));
      c.total++;
      if (cat==='Completed') c.completed++;
      else if (cat==='In Progress') c.in_progress++;
      else if (cat==='Waiting For Approval') c.waiting_for_approval++;
      else c.open++;
      if (_LIVE.isOverdue(issue)) c.overdue++;
      c.statuses[sname] = (c.statuses[sname]||0)+1;
    }
    const people = {};
    let grandTotal=0, grandDone=0;
    for (const [name,c] of Object.entries(counts)){
      const pct = c.total ? Math.round(1000*c.completed/c.total)/10 : 0;
      people[name] = {total:c.total,open:c.open,in_progress:c.in_progress,waiting_for_approval:c.waiting_for_approval,overdue:c.overdue,completed:c.completed,pct,done:c.completed,statuses:c.statuses,issues:c.issues,hidden:hidden.has(name)};
      if (!hidden.has(name)){ grandTotal+=c.total; grandDone+=c.completed; }
    }
    const teamPct = grandTotal ? Math.round(1000*grandDone/grandTotal)/10 : 0;
    return {people, teamPct, grandTotal, grandDone};
  },
  parsePrev(v){
    if (v===null||v===undefined) return null;
    if (typeof v === 'object') return v;
    return {pct:parseFloat(v),done:null,total:null,open:0,in_progress:0,waiting_for_approval:0,overdue:0,completed:null,statuses:{}};
  },
  findBaseline(history, todayStr){
    const all = history || [];
    // 1) Admin-pinned baseline wins (persists in schedule.json, survives refresh).
    //    "latest" auto-follows the newest snapshot before today; a specific
    //    date matches ANY snapshot, including today's (explicit choice).
    if (typeof _PINNED_BASELINE !== 'undefined' && _PINNED_BASELINE) {
      if (String(_PINNED_BASELINE).toLowerCase() === 'latest') {
        const prior = all.filter(s => (s.date||'') < todayStr);
        if (prior.length) return prior[prior.length-1];
      } else {
        const pin = all.find(s => s.date === _PINNED_BASELINE);
        if (pin) return pin;
      }
    }
    const prior = all.filter(s => (s.date||'') < todayStr);
    if (!prior.length) return null;
    // 2) Most recent prior snapshot on the configured weekly day.
    if (typeof _WEEKLY_DAY !== 'undefined' && _WEEKLY_DAY !== null) {
      const onDay = prior.filter(s => { const d=new Date(s.date+'T00:00:00'); return !isNaN(d) && d.getDay()===_WEEKLY_DAY; });
      if (onDay.length) return onDay[onDay.length-1];
    }
    // 3) Fallbacks: last weekly-tagged, then most recent prior.
    const weekly = prior.filter(s => s.is_weekly);
    return weekly.length ? weekly[weekly.length-1] : prior[prior.length-1];
  },
  // Build the same REPORT shape build_report() produces. NOTE: unlike Python we
  // do NOT save a history snapshot here — the weekly job owns the canonical
  // history; live recompute only reads it to draw week-over-week deltas.
  buildReport(issues, history, hiddenSet, jiraBaseUrl){
    const {people, teamPct, grandTotal, grandDone} = _LIVE.computeRates(issues, hiddenSet);
    const now = new Date();
    const today = now.toISOString().slice(0,10);
    const lastSnap = _LIVE.findBaseline(history, today);
    const lastPeople = lastSnap ? (lastSnap.people||{}) : {};
    let lastTeam = null;
    if (lastSnap){
      let tot=0, done=0;
      for (const [n,p] of Object.entries(lastPeople)){
        if (hiddenSet && hiddenSet.has(n)) continue;
        if (p && typeof p === 'object'){
          tot += p.total||0;
          done += (p.done!=null ? p.done : (p.completed||0));
        }
      }
      lastTeam = tot ? Math.round(1000*done/tot)/10 : null;
    }
    const rows = [];
    for (const name of Object.keys(people).sort((a,b)=>a.toLowerCase()<b.toLowerCase()?-1:1)){
      const t = people[name];
      const prev = _LIVE.parsePrev(lastPeople[name]);
      const delta = prev!=null ? Math.round((t.pct - prev.pct)*10)/10 : null;
      const lp = (k,def=0)=> prev==null ? def : (prev[k]!=null?prev[k]:def);
      rows.push({
        owner:name,
        total:t.total, open:t.open, in_progress:t.in_progress,
        waiting_for_approval:t.waiting_for_approval, overdue:t.overdue,
        completed:t.completed, this_week:t.pct,
        last_week: prev?prev.pct:null,
        last_total:lp('total'), last_open:lp('open'), last_in_progress:lp('in_progress'),
        last_wfa:lp('waiting_for_approval'), last_overdue:lp('overdue'), last_completed:lp('completed'),
        delta, done:t.completed, statuses:t.statuses, issues:t.issues,
        hidden:t.hidden, last_statuses: prev?(prev.statuses||{}):{},
      });
    }
    const teamDelta = lastTeam!=null ? Math.round((teamPct-lastTeam)*10)/10 : null;
    return {
      date: today,
      timestamp: now.toISOString(),
      jira_base_url: jiraBaseUrl || (typeof REPORT!=='undefined' && REPORT && REPORT.jira_base_url) || 'https://fibtask.atlassian.net',
      last_snap_date: lastSnap?lastSnap.date:null,
      last_snap_time: lastSnap?(lastSnap.timestamp||null):null,
      team_total: teamPct, team_last_week: lastTeam, team_delta: teamDelta,
      grand_total: grandTotal, grand_done: grandDone,
      rows, has_previous: lastSnap!=null,
      is_today_weekly: now.getUTCDay()===3,
      history: history||[],
    };
  },
};

// Pull fresh issues from the Worker (read-only Jira proxy). Returns issues[].
async function fetchLiveIssues(){
  if (!GH_PROXY) throw new Error('No Worker proxy configured (meta gh-proxy).');
  const pw = sessionStorage.getItem('pw_cache') || '';
  // Call the Worker directly — the global fetch wrapper only rewrites
  // api.github.com URLs, so this passes straight through.
  const r = await window.fetch(GH_PROXY, {
    method:'POST',
    headers:{'Content-Type':'application/json','X-Proxy-Auth':pw},
    body: JSON.stringify({action:'jira'})
  });
  if (!r.ok){
    let msg = 'HTTP '+r.status;
    try { const j = await r.json(); if (j.message) msg = j.message + (j.detail?(' — '+j.detail):''); } catch(e){}
    throw new Error(msg);
  }
  const j = await r.json();
  return j.issues || [];
}

let _LIVE_AUTO_TIMER = null;
let _LIVE_BUSY = false;

// Fetch live issues, recompute REPORT, and re-render in place (no reload).
async function refreshLive(btn){
  if (!GH_PROXY){ toast('Live refresh needs the Cloudflare Worker (meta gh-proxy).'); return; }
  if (_LIVE_BUSY) return;
  _LIVE_BUSY = true;
  // Turn the LIVE chip RED + "loading…" while we pull from Jira.
  const liveChip = document.getElementById('live-chip');
  const liveAgo  = document.getElementById('live-ago');
  if (liveChip) liveChip.classList.add('loading');
  if (liveAgo)  liveAgo.textContent = 'loading…';
  const label = btn ? btn.querySelector('.rl-txt') : null;
  const orig  = label ? label.textContent : '';
  if (label) label.textContent = 'Fetching…';
  if (btn) btn.disabled = true;
  try {
    const issues  = await fetchLiveIssues();
    const hidden  = (hiddenPeople && hiddenPeople.size) ? hiddenPeople : new Set();
    const history = (typeof REPORT!=='undefined' && REPORT && REPORT.history) ? REPORT.history : [];
    const base    = (typeof REPORT!=='undefined' && REPORT && REPORT.jira_base_url) || '';
    REPORT = _LIVE.buildReport(issues, history, hidden, base);
    window._LIVE_FETCHED_AT = Date.now();   // LIVE chip counts from this moment
    init();   // full re-render from the fresh REPORT (ANALYSIS stays as-is)
    toast(`✓ Live · ${issues.length} issues · team ${REPORT.team_total}%`);
  } catch(e){
    toast('Live refresh failed: ' + (e.message||e));
  } finally {
    if (liveChip) liveChip.classList.remove('loading');   // back to green LIVE
    if (label) label.textContent = orig;
    if (btn) btn.disabled = false;
    _LIVE_BUSY = false;
  }
}

// Toggle a 2-minute auto-refresh. Skips ticks while the tab is hidden or a
// modal is open, so it never yanks data out from under the user.
// Live auto-refresh is ALWAYS ON and cannot be turned off — it pulls fresh
// Jira data every 10s. Skips a tick while the tab is hidden
// or a modal is open so it never yanks data out from under the user.
function startLiveAuto(){
  if (_LIVE_AUTO_TIMER) return;
  refreshLive();
  _LIVE_AUTO_TIMER = setInterval(()=>{
    if (document.visibilityState==='visible' && !document.querySelector('.modal-overlay:not(.hidden)'))
      refreshLive();
  }, 10000);
}

// ── Ask-AI dock (DeepSeek, proxied through the Worker so the key stays a
// Worker secret — never in this page). Hover the orb to peek; click to pin.
// The model is handed a compact snapshot of the CURRENT dashboard as context,
// plus any pasted images, so it can answer about live numbers. ──
let _AI_HISTORY = [];   // [{role, content}] — last few turns for follow-ups
let _AI_IMAGES  = [];   // images pasted for the NEXT message (data URLs)
let _AI_BUSY    = false;

function aiTogglePin(){
  const dock = document.getElementById('ai-dock');
  if (!dock) return;
  if (dock.classList.contains('pinned')) {        // pinned open → close
    dock.classList.remove('pinned');
    dock.classList.remove('open');
  } else {                                         // → open + pin
    dock.classList.add('pinned');
    dock.classList.add('open');
    const inp = document.getElementById('ai-q');
    if (inp) setTimeout(()=>inp.focus(), 60);
  }
}
function aiUnpin(){                                 // the X button / Esc — collapse
  const dock = document.getElementById('ai-dock');
  if (dock){ dock.classList.remove('pinned'); dock.classList.remove('open'); }
}
// Esc closes the panel.
document.addEventListener('keydown', e => { if (e.key === 'Escape') aiUnpin(); });

// Full, task-level snapshot the model can answer ANYTHING from. Built from the
// in-memory report (no network) — the caller fetches fresh data on demand.
function _aiContext(rep){
  const R = rep || (typeof REPORT !== 'undefined' ? REPORT : null);
  if (!R) return 'No data loaded yet.';
  const out = [];
  out.push(`Jira project dashboard (${R.jira_base_url||''}). Report date: ${R.date}.`);
  out.push(`Team completion: ${R.team_total}%` +
    (R.team_last_week!=null ? ` (last period ${R.team_last_week}%, change ${R.team_delta>0?'+':''}${R.team_delta}%)` : ' (no prior period)') + '.');
  out.push(`Team totals: ${R.grand_done}/${R.grand_total} tasks done.`);
  out.push('', 'PER PERSON:');
  (R.rows||[]).forEach(r => {
    out.push(`- ${r.owner}: ${r.this_week}% (${r.completed}/${r.total} done), open ${r.open}, in-progress ${r.in_progress}, waiting-for-approval ${r.waiting_for_approval}, overdue ${r.overdue}` +
      (r.delta!=null ? `, change ${r.delta>0?'+':''}${r.delta}%` : ', NEW') + (r.hidden ? ' [hidden]' : ''));
  });
  // Task-level lines so it can answer specifics (who/what/which task/overdue).
  out.push('', 'TASKS (key | owner | status | category | due | flag | summary):');
  let n = 0;
  (R.rows||[]).forEach(r => (r.issues||[]).forEach(it => {
    if (n++ < 800)
      out.push(`${it.key} | ${r.owner} | ${it.status} | ${it.category} | ${it.due||'—'} | ${it.overdue?'OVERDUE':'-'} | ${(it.summary||'').slice(0,90)}`);
  }));
  return out.join('\n');
}

// Paste-an-image support: pull image blobs off the clipboard into _AI_IMAGES.
function _aiPaste(e){
  const items = (e.clipboardData && e.clipboardData.items) || [];
  for (const it of items){
    if (it.type && it.type.indexOf('image/') === 0){
      const file = it.getAsFile();
      if (!file) continue;
      const reader = new FileReader();
      reader.onload = ev => { _AI_IMAGES.push(ev.target.result); _aiRenderThumbs(); };
      reader.readAsDataURL(file);
      e.preventDefault();
    }
  }
}
function _aiRenderThumbs(){
  const wrap = document.getElementById('ai-attach');
  if (!wrap) return;
  wrap.innerHTML = _AI_IMAGES.map((src,i) =>
    `<div class="ai-thumb"><img src="${src}" alt=""><button onclick="_aiRemoveImg(${i})" title="Remove">&times;</button></div>`
  ).join('');
}
function _aiRemoveImg(i){ _AI_IMAGES.splice(i,1); _aiRenderThumbs(); }

function _aiAppend(role, text, images){
  const box = document.getElementById('ai-msgs');
  const div = document.createElement('div');
  div.className = 'ai-msg ' + (role==='user' ? 'ai-msg-user' : role==='err' ? 'ai-msg-err' : 'ai-msg-bot');
  if (text) div.textContent = text;
  (images||[]).forEach(src => { const im = document.createElement('img'); im.src = src; div.appendChild(im); });
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
  return div;
}

async function sendAI(){
  if (_AI_BUSY) return;
  const inp = document.getElementById('ai-q');
  const q = (inp.value||'').trim();
  if (!q && !_AI_IMAGES.length) return;
  if (!GH_PROXY){ toast('AI needs the Cloudflare Worker (meta gh-proxy).'); return; }
  const imgs = _AI_IMAGES.slice();
  inp.value = '';
  _AI_IMAGES = []; _aiRenderThumbs();
  const dock = document.getElementById('ai-dock'); if (dock){ dock.classList.add('pinned'); dock.classList.add('open'); }
  _aiAppend('user', q, imgs);

  // OpenAI-style multimodal content when images are attached, else plain text.
  let userContent;
  if (imgs.length){
    userContent = [];
    if (q) userContent.push({type:'text', text:q});
    imgs.forEach(src => userContent.push({type:'image_url', image_url:{url:src}}));
  } else {
    userContent = q;
  }
  _AI_HISTORY.push({role:'user', content:userContent});
  const pending = _aiAppend('bot', '…');
  _AI_BUSY = true;
  // Fetch fresh data ONLY now, on demand — never on page load or auto-refresh —
  // so the AI always answers about the current state without wasting API calls.
  // Falls back to the in-memory report if the live fetch is unavailable.
  let rep = (typeof REPORT !== 'undefined') ? REPORT : null;
  try {
    if (GH_PROXY) {
      const issues  = await fetchLiveIssues();
      const hidden  = (hiddenPeople && hiddenPeople.size) ? hiddenPeople : new Set();
      const history = (rep && rep.history) ? rep.history : [];
      rep = _LIVE.buildReport(issues, history, hidden, (rep && rep.jira_base_url) || '');
    }
  } catch(e){ /* keep in-memory rep */ }
  const sys = { role:'system', content:
    'You are the project assistant for a Jira weekly-progress dashboard. You have ' +
    'full team stats AND task-level data below — use it to answer ANY question about ' +
    'the project. If something truly is not in the data, say so. Be concise and friendly.' +
    '\n\n=== PROJECT DATA ===\n' + _aiContext(rep) };
  try {
    const pw = sessionStorage.getItem('pw_cache') || '';
    const r = await window.fetch(GH_PROXY, {
      method:'POST',
      headers:{'Content-Type':'application/json','X-Proxy-Auth':pw},
      body: JSON.stringify({ action:'deepseek', messages:[sys, ..._AI_HISTORY.slice(-8)] })
    });
    const j = await r.json().catch(()=>({}));
    if (!r.ok) throw new Error(j.message ? (j.message + (j.detail?(' — '+j.detail):'')) : ('HTTP '+r.status));
    const reply = (j.reply || '').trim() || '(no answer)';
    pending.textContent = reply;
    _AI_HISTORY.push({role:'assistant', content:reply});
  } catch(e){
    pending.textContent = '⚠ ' + (e.message||e);
    pending.classList.remove('ai-msg-bot');
    pending.classList.add('ai-msg-err');
  } finally {
    _AI_BUSY = false;
  }
}

// Current local time as "HH:MM" — embedded in every exported image so a paste
// shows when the snapshot was captured, not just the date.
function _nowHM() {
  const d = new Date();
  const p = n => String(n).padStart(2,'0');
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}
function _nowDateTime() { return `${REPORT?.date || new Date().toISOString().slice(0,10)} ${_nowHM()}`; }

// ── decrypt helpers (WebCrypto, matches Python PBKDF2-SHA256 + AES-GCM) ────
function _b64dec(s){ return Uint8Array.from(atob(s), c=>c.charCodeAt(0)); }
async function _deriveKey(password, salt, iter){
  const km = await crypto.subtle.importKey('raw',
    new TextEncoder().encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:iter, hash:'SHA-256'},
    km, {name:'AES-GCM', length:256}, false, ['decrypt']);
}
async function decryptBlob(blob, password){
  const salt  = _b64dec(blob.salt);
  const nonce = _b64dec(blob.nonce);
  const ct    = _b64dec(blob.ct);
  const key   = await _deriveKey(password, salt, blob.iter);
  const pt    = await crypto.subtle.decrypt({name:'AES-GCM', iv:nonce}, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}
// Encrypt counterpart — produces the same {salt,nonce,ct,iter} shape the
// Python crypto_store / decryptBlob read. Used to write encrypted data stores
// (e.g. history.json.enc) back to the repo from the dashboard.
function _b64enc(bytes){ let s=''; const b=new Uint8Array(bytes); for(let i=0;i<b.length;i++) s+=String.fromCharCode(b[i]); return btoa(s); }
async function encryptBlob(obj, password){
  const iter  = 600000;
  const salt  = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const km = await crypto.subtle.importKey('raw',
    new TextEncoder().encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:iter, hash:'SHA-256'},
    km, {name:'AES-GCM', length:256}, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv:nonce}, key,
    new TextEncoder().encode(JSON.stringify(obj)));
  return { salt:_b64enc(salt), nonce:_b64enc(nonce), ct:_b64enc(ct), iter };
}
// ── Encrypted data stores (data/<name>.enc) — read/write from the dashboard ──
// Centralised so every confidential store uses one audited crypto path.
async function _loadEncStore(name, ref){
  const repo = document.querySelector('meta[name=repo]')?.content||'';
  const pw   = sessionStorage.getItem('pw_cache');
  if (!repo || !pw) return null;
  const headers = {'Accept':'application/vnd.github+json'};
  if (GH_PAT) headers['Authorization'] = `Bearer ${GH_PAT}`;
  try {
    const q = ref ? `?ref=${ref}` : '';
    const r = await fetch(`https://api.github.com/repos/${repo}/contents/data/${name}.enc${q}`,
                          {headers, cache:'no-store'});
    if (!r.ok) return null;
    const j = await r.json();
    const txt = decodeURIComponent(Array.from(atob((j.content||'').replace(/\s/g,'')))
      .map(c => '%' + c.charCodeAt(0).toString(16).padStart(2,'0')).join(''));
    return await decryptBlob(JSON.parse(txt), pw);
  } catch(e){ console.warn('[encstore] load '+name, e); return null; }
}
async function _saveEncStore(name, data, message){
  const repo = document.querySelector('meta[name=repo]')?.content||'';
  const pw   = sessionStorage.getItem('pw_cache');
  if (!repo)   { toast('Repo not configured.'); return false; }
  if (!GH_PAT) { toast('No token — re-enter password.'); return false; }
  if (!pw)     { toast('Session expired — reload and re-enter the password.'); return false; }
  const headers = {'Authorization':`Bearer ${GH_PAT}`,'Accept':'application/vnd.github+json'};
  const blob = await encryptBlob(data, pw);
  const content = btoa(unescape(encodeURIComponent(JSON.stringify(blob) + '\n')));
  const url = `https://api.github.com/repos/${repo}/contents/data/${name}.enc`;
  // Retry on 409: the file's sha can move because a workflow cleared the queue
  // between our read and write. Without this the save silently fails under churn.
  for (let attempt=0; attempt<5; attempt++){
    let sha = null;
    try { const g = await fetch(url, {headers, cache:'no-store'}); if (g.ok) sha = (await g.json()).sha; } catch(e){}
    const p = await fetch(url, {
      method:'PUT',
      headers:{...headers, 'Content-Type':'application/json'},
      body: JSON.stringify({ message: message || ('Update ' + name), content, sha })
    });
    if (p.ok) return true;
    const e = await p.json().catch(()=>({}));
    if (p.status === 409 || /does not match|sha/i.test(e.message||'')) {
      await new Promise(r => setTimeout(r, 400*(attempt+1)));   // conflict → re-read sha & retry
      continue;
    }
    toast('Save failed: '+(e.message||p.status));
    return false;
  }
  toast('Save failed: conflict after retries — please try again.');
  return false;
}

// ── password gate ──────────────────────────────────────────────────────────
async function checkPw(){
  const inp = document.getElementById('pw-inp');
  const err = document.getElementById('pw-err');
  const v   = inp.value;
  // Hidden shortcut — input is hashed and the destination is encrypted, so
  // neither the word nor the URL is readable in this page's source.
  {
    const _S = {h:"ad94a20a343951816a59c46c9681cfd222fa8f771d9dd6b4a7b2b51ea9c529fe",
                s:"MaLa0tKRqGNQOZ7K8IA+rQ==",i:"H/lmJC8SOC6fLq9X",
                c:"Fsxl4NFyVs2qa3aQua/wWzkz6hw3F2cfT6trk8bL2r2P8rR6SXqP8czdBPq3AEAviHI3yNB1ufXI5UDSkdQdJLjDOOFMYQ==",it:100000};
    const _t = v.trim().toLowerCase();
    const _d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(_t));
    const _hex = Array.from(new Uint8Array(_d)).map(x=>x.toString(16).padStart(2,'0')).join('');
    if (_hex === _S.h) {
      const _u = s => { const r=atob(s),a=new Uint8Array(r.length); for(let k=0;k<r.length;k++)a[k]=r.charCodeAt(k); return a; };
      const _km = await crypto.subtle.importKey('raw', new TextEncoder().encode(_t), 'PBKDF2', false, ['deriveKey']);
      const _k = await crypto.subtle.deriveKey({name:'PBKDF2',salt:_u(_S.s),iterations:_S.it,hash:'SHA-256'},
        _km, {name:'AES-GCM',length:256}, false, ['decrypt']);
      const _pt = await crypto.subtle.decrypt({name:'AES-GCM',iv:_u(_S.i)}, _k, _u(_S.c));
      window.location.href = new TextDecoder().decode(_pt);
      return;
    }
  }
  if (!v) return;
  err.textContent = 'Decrypting…';
  try {
    const data = await decryptBlob(ENC_BLOB, v);
    REPORT   = data.report;
    ANALYSIS = data.analysis;
    // With the proxy, the page has no PAT — use the site password as the proxy
    // credential so the existing "if (!GH_PAT)" guards still pass.
    GH_PAT   = data.pat || (GH_PROXY ? v : '');
    // Apply hidden list from build-time embedding as baseline
    if (Array.isArray(data.hidden)) {
      hiddenPeople.clear();
      data.hidden.forEach(n => hiddenPeople.add(n));
    }
    sessionStorage.setItem('pw_cache', v);
    err.textContent = '';
    // Then try to refresh from API for any live changes since build
    await _loadHiddenListRemote();
    unlock();
    init();
  } catch(e){
    err.textContent = 'Incorrect password — try again.';
    inp.value = '';
    inp.focus();
    setTimeout(()=>err.textContent='', 3000);
  }
}
function playIntro(){
  var s = document.getElementById('intro-splash');
  if (!s) return;
  s.classList.add('on');
  setTimeout(function(){ s.style.display = 'none'; }, 3600);
}
function unlock(){
  document.getElementById('pw-overlay').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  playIntro();
}
// Require the password on every page load (including refresh): clear any
// cached credential so the gate is always shown until the user re-enters it.
document.addEventListener('DOMContentLoaded', () => {
  sessionStorage.removeItem('pw_cache');
});

// ── modal helpers ──────────────────────────────────────────────────────────
function openModal(id)  { document.getElementById(id).classList.remove('hidden'); }
function closeModal(id) { document.getElementById(id).classList.add('hidden'); }

// ── "More" menu (top-bar dropdown) ─────────────────────────────────────────
function toggleMoreMenu(e) {
  if (e) e.stopPropagation();
  document.getElementById('more-menu').classList.toggle('show');
}
function closeMoreMenu() {
  document.getElementById('more-menu').classList.remove('show');
}
document.addEventListener('click', (e) => {
  if (!e.target.closest('.menu-dropdown')) closeMoreMenu();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeMoreMenu();
});
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.modal-overlay').forEach(el => {
    el.addEventListener('click', e => { if (e.target===el) el.classList.add('hidden'); });
  });
});

// ── helpers ────────────────────────────────────────────────────────────────
const esc = s => { const d=document.createElement('div'); d.textContent=s; return d.innerHTML; };
function toast(msg, ms=3500) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), ms);
}

function pStyle(delta, thisWeek, isNew) {
  // 100% complete → always neutral (white row), regardless of delta
  if (thisWeek >= 100 && !isNew && delta >= 0)
    return {row:'', pct:'pct-neutral', d:'d-flat-ok', dt: delta>0?`+${delta}%`:'±0%', bar:'bar-green'};
  if (isNew || delta===null || delta===undefined)
    return {row:'', pct:'pct-neutral', d:'d-new', dt:'NEW', bar:'bar-blue'};
  if (delta > 0)
    return {row:'row-green', pct:'pct-green', d:'d-up', dt:`+${delta}%`, bar:'bar-green'};
  if (delta < 0)
    return {row:'row-red', pct:'pct-red', d:'d-down', dt:`${delta}%`, bar:'bar-red'};
  // delta === 0 and < 100
  return {row:'row-red', pct:'pct-red', d:'d-flat-bad', dt:'±0%', bar:'bar-red'};
}

function numTD(n, bold=false) {
  const b = bold ? ' bold' : '';
  if (!n) return `<td class="c zero${b}">0</td>`;
  return `<td class="c${b}">${n}</td>`;
}

function ovTD(n) {
  if (!n) return `<td class="c"><span class="ov-zero">0</span></td>`;
  return `<td class="c"><span class="ov-badge">${n}</span></td>`;
}

function deltaTD(curr, prev, suffix='') {
  if (prev===null||prev===undefined) return `<td class="c"><span class="delta d-new">NEW</span></td>`;
  const d = Math.round((curr - prev)*10)/10;
  const cls = d>0?'d-up':d<0?'d-down':'d-flat-ok';
  const t = d>0?`+${d}${suffix}`:d===0?`±0${suffix}`:`${d}${suffix}`;
  return `<td class="c"><span class="delta ${cls}">${t}</span></td>`;
}

// Live timestamp shown next to the PMO Analytics Dashboard title.
function _updateAnalyticsTime() {
  const el = document.getElementById('analytics-time');
  if (!el) return;
  const d = new Date();
  const pad = n => String(n).padStart(2,'0');
  const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  el.textContent = `🕒 ${days[d.getDay()]} ${d.toISOString().slice(0,10)} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
if (!window._analyticsTimeTimer) {
  window._analyticsTimeTimer = setInterval(_updateAnalyticsTime, 30000);
  document.addEventListener('DOMContentLoaded', _updateAnalyticsTime);
  setTimeout(_updateAnalyticsTime, 0);
}

// Copy the analytics dashboard (donut + PMO panel) as rich HTML for Outlook.
async function copyAnalyticsDashboard(btn) {
  const txt = document.getElementById('analytics-copy-txt');
  const orig = txt ? txt.textContent : 'Copy';
  if (txt) txt.textContent = '… capturing';
  try {
    const cv = _drawDashboardCanvas(true);
    if (!cv) { toast('No data to copy.'); return; }
    await _copyCanvasToClipboard(cv, `analytics-dashboard-${REPORT.date}.png`);
    if (txt) { txt.textContent = '✓ Copied'; setTimeout(()=>txt.textContent=orig, 1400); }
  } catch(e) {
    console.error('[copy-analytics]', e);
    toast('Copy failed: '+e.message);
    if (txt) txt.textContent = orig;
  }
}

// ── Analytics: donut + top/bottom performer bars ───────────────────────────
function renderDonut() {
  _updateAnalyticsTime();
  const rows = REPORT.rows;
  const totals = rows.reduce((acc, r) => {
    acc.open += r.open||0;
    acc.in_progress += r.in_progress||0;
    acc.wfa += r.waiting_for_approval||0;
    acc.done += r.completed||0;
    return acc;
  }, {open:0, in_progress:0, wfa:0, done:0});
  const total = totals.open + totals.in_progress + totals.wfa + totals.done;
  const wrap = document.getElementById('donut-wrap');
  if (!total) { wrap.innerHTML = '<div class="empty" style="padding:20px">No tasks.</div>'; return; }

  const segs = [
    {label:'Completed',   val:totals.done,        color:'#10b981'},
    {label:'In Progress', val:totals.in_progress, color:'#3b82f6'},
    {label:'Waiting',     val:totals.wfa,         color:'#f59e0b'},
    {label:'Open',        val:totals.open,        color:'#94a3b8'},
  ];
  const r = 78, cx = 100, cy = 100, sw = 28;
  let acc = 0;
  let paths = '';
  segs.forEach(s => {
    if (s.val <= 0) return;
    const a1 = acc/total * 2*Math.PI - Math.PI/2;
    acc += s.val;
    const a2 = acc/total * 2*Math.PI - Math.PI/2;
    const large = (s.val/total > 0.5) ? 1 : 0;
    const x1 = cx + r*Math.cos(a1), y1 = cy + r*Math.sin(a1);
    const x2 = cx + r*Math.cos(a2), y2 = cy + r*Math.sin(a2);
    const ir = r - sw;
    const ix1 = cx + ir*Math.cos(a1), iy1 = cy + ir*Math.sin(a1);
    const ix2 = cx + ir*Math.cos(a2), iy2 = cy + ir*Math.sin(a2);
    // Full-circle edge case (one segment is 100%): use two arcs
    if (s.val === total) {
      paths += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${s.color}" />
                <circle cx="${cx}" cy="${cy}" r="${ir}" fill="#fff" />`;
    } else {
      paths += `<path d="M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} L ${ix2} ${iy2} A ${ir} ${ir} 0 ${large} 0 ${ix1} ${iy1} Z" fill="${s.color}" />`;
    }
  });
  const pctDone = Math.round(totals.done/total*100);
  wrap.innerHTML = `<svg viewBox="0 0 200 200" width="200" height="200">
    ${paths}
    <text x="${cx}" y="${cy-2}" text-anchor="middle" font-size="32" font-weight="800" fill="#0f172a" font-family="Inter,sans-serif">${pctDone}%</text>
    <text x="${cx}" y="${cy+18}" text-anchor="middle" font-size="11" fill="#64748b" font-family="Inter,sans-serif">Completed</text>
  </svg>
  <div class="donut-legend">
    ${segs.map(s=>`<div class="donut-row">
      <span class="donut-row-sw" style="background:${s.color}"></span>
      <span class="donut-row-name">${s.label}</span>
      <span class="donut-row-val">${s.val} <span style="color:#94a3b8;font-weight:500">(${Math.round(s.val/total*100)}%)</span></span>
    </div>`).join('')}
    <div class="donut-row" style="border-top:1px solid #e2e8f0;padding-top:6px;margin-top:4px">
      <span class="donut-row-name" style="color:#0f172a;font-weight:700">Total tasks</span>
      <span class="donut-row-val">${total}</span>
    </div>
  </div>`;
}

// ── PMO Health Dashboard (RAG + KPIs + Escalation) ─────────────────────────
// Persisted across re-renders (live refresh, snapshot switches, etc.) so the
// watchlist doesn't silently collapse back to top-5 every time fresh data comes in.
let _pmoWatchlistExpanded = false;
function _togglePmoWatchlist() {
  _pmoWatchlistExpanded = !_pmoWatchlistExpanded;
  renderPMOPanel();
}
function renderPMOPanel() {
  const wrap = document.getElementById('pmo-wrap');
  const rows = REPORT.rows.filter(r => r.owner !== 'Unassigned' && (r.total||0) > 0 && !hiddenPeople.has(r.owner));
  if (!rows.length) { wrap.innerHTML = '<div class="empty">No data.</div>'; return; }

  // ── RAG Classification (industry-standard PMO thresholds) ──
  // Green: ≥80% complete AND ≤1 overdue
  // Amber: 50–79% complete AND ≤3 overdue, OR negative weekly trend
  // Red:   <50% complete OR ≥4 overdue OR stuck-at-0 below 100%
  const rag = {green:[], amber:[], red:[]};
  rows.forEach(r => {
    const pct = r.this_week || 0;
    const ov  = r.overdue || 0;
    const d   = r.delta;
    if (pct >= 80 && ov <= 1) rag.green.push(r);
    else if (pct < 50 || ov >= 4 || (d === 0 && pct < 50)) rag.red.push(r);
    else rag.amber.push(r);
  });
  const total = rows.length;
  const pctG = (rag.green.length/total*100).toFixed(0);
  const pctA = (rag.amber.length/total*100).toFixed(0);
  const pctR = (rag.red.length/total*100).toFixed(0);

  // ── KPIs ──
  const gTotal = rows.reduce((s,r)=>s+(r.total||0),0);
  const gDone  = rows.reduce((s,r)=>s+(r.completed||0),0);
  const gOpen  = rows.reduce((s,r)=>s+(r.open||0),0);
  const gIP    = rows.reduce((s,r)=>s+(r.in_progress||0),0);
  const gWFA   = rows.reduce((s,r)=>s+(r.waiting_for_approval||0),0);
  const gOv    = rows.reduce((s,r)=>s+(r.overdue||0),0);
  const completion = gTotal ? +(gDone/gTotal*100).toFixed(1) : 0;
  const overdueRate = gTotal ? +(gOv/gTotal*100).toFixed(1) : 0;
  const wipRatio = gTotal ? +(gIP/gTotal*100).toFixed(1) : 0;
  // workload imbalance: coefficient of variation of tasks-per-member
  const counts = rows.map(r => r.total||0);
  const mean = counts.reduce((a,b)=>a+b,0)/counts.length;
  const variance = counts.reduce((s,x)=>s+Math.pow(x-mean,2),0)/counts.length;
  const cv = mean>0 ? +(Math.sqrt(variance)/mean*100).toFixed(0) : 0;

  const compClass = completion >= 80 ? 'kpi-good' : completion >= 50 ? 'kpi-warn' : 'kpi-bad';
  const ovClass   = overdueRate <= 5 ? 'kpi-good' : overdueRate <= 15 ? 'kpi-warn' : 'kpi-bad';
  const wipClass  = wipRatio <= 20 ? 'kpi-good' : wipRatio <= 35 ? 'kpi-warn' : 'kpi-bad';
  const wfaClass  = gWFA <= 3 ? 'kpi-good' : gWFA <= 8 ? 'kpi-warn' : 'kpi-bad';

  // ── Escalation watchlist (PMO action items) ──
  // All rows with at least 1 overdue — these always appear in the watchlist.
  // Rows with NO overdue but with other concerns (low %, negative WoW) also appear.
  const watchlistFull = rows.slice().map(r => {
    const reasons = [];
    const pct = r.this_week||0;
    const ov = r.overdue||0;
    const d = r.delta;
    if (ov >= 4) reasons.push({txt:`${ov} overdue`, cls:'esc-chip'});
    else if (ov >= 2) reasons.push({txt:`${ov} overdue`, cls:'esc-chip amber'});
    else if (ov === 1) reasons.push({txt:`1 overdue`, cls:'esc-chip amber'});
    if (pct < 30) reasons.push({txt:`only ${pct}%`, cls:'esc-chip'});
    else if (pct < 50) reasons.push({txt:`${pct}%`, cls:'esc-chip amber'});
    if (d !== null && d !== undefined && d < -5) reasons.push({txt:`${d}% WoW`, cls:'esc-chip'});
    if (pct === 0 && (r.total||0) > 2) reasons.push({txt:'no progress', cls:'esc-chip'});
    const score = ov*15 + Math.max(0,50-pct) + (d<0?Math.abs(d)*2:0);
    return {...r, _reasons: reasons, _score: score};
  }).filter(r => r._reasons.length > 0)
    .sort((a,b) => b._score - a._score);
  const watchlist = _pmoWatchlistExpanded ? watchlistFull : watchlistFull.slice(0, 5);
  const hiddenCount = watchlistFull.length - watchlist.length;

  // ── Render ──
  wrap.innerHTML = `
    <div class="pmo-section">
      <div class="pmo-section-title">🚦 RAG Status Distribution</div>
      <div class="rag-bar">
        ${rag.green.length ? `<div class="rag-seg rag-seg-g" style="flex:${rag.green.length}" title="Green: ${rag.green.length} healthy">${pctG}%</div>`:''}
        ${rag.amber.length ? `<div class="rag-seg rag-seg-a" style="flex:${rag.amber.length}" title="Amber: ${rag.amber.length} watch">${pctA}%</div>`:''}
        ${rag.red.length   ? `<div class="rag-seg rag-seg-r" style="flex:${rag.red.length}"   title="Red: ${rag.red.length} at risk">${pctR}%</div>`:''}
      </div>
      <div class="rag-legend">
        <span><span class="rag-legend-dot" style="background:#059669"></span><strong>${rag.green.length}</strong> Healthy (≥80%, ≤1 overdue)</span>
        <span><span class="rag-legend-dot" style="background:#d97706"></span><strong>${rag.amber.length}</strong> Watch</span>
        <span><span class="rag-legend-dot" style="background:#dc2626"></span><strong>${rag.red.length}</strong> At Risk</span>
      </div>
    </div>

    <div class="pmo-section">
      <div class="pmo-section-title">📊 Key Performance Indicators</div>
      <div class="kpi-grid">
        <div class="kpi-tile">
          <div class="kpi-tile-label">Completion</div>
          <div class="kpi-tile-value ${compClass}">${completion}%</div>
          <div class="kpi-tile-sub">${gDone} / ${gTotal} tasks</div>
        </div>
        <div class="kpi-tile">
          <div class="kpi-tile-label">Overdue Rate</div>
          <div class="kpi-tile-value ${ovClass}">${overdueRate}%</div>
          <div class="kpi-tile-sub">${gOv} of ${gTotal} past due</div>
        </div>
        <div class="kpi-tile">
          <div class="kpi-tile-label">WIP Ratio</div>
          <div class="kpi-tile-value ${wipClass}">${wipRatio}%</div>
          <div class="kpi-tile-sub">${gIP} in progress</div>
        </div>
        <div class="kpi-tile">
          <div class="kpi-tile-label">Approval Queue</div>
          <div class="kpi-tile-value ${wfaClass}">${gWFA}</div>
          <div class="kpi-tile-sub">waiting for sign-off</div>
        </div>
      </div>
    </div>

    ${watchlist.length ? `
    <div class="pmo-section">
      <div class="pmo-section-title">⚠ Escalation Watchlist (PM Action Required)</div>
      <div class="esc-list">
        ${watchlist.map((r,i) => {
          const amber = r._reasons.every(x => x.cls.includes('amber'));
          return `<div class="esc-row ${amber?'amber':''}" role="button" tabindex="0"
                  style="cursor:pointer"
                  onclick="openPersonModal('${esc(r.owner).replace(/'/g,"\\'")}')"
                  onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();openPersonModal('${esc(r.owner).replace(/'/g,"\\'")}')}"
                  title="Click to view all assigned tasks for ${esc(r.owner)}">
            <span class="esc-rank">#${i+1}</span>
            <span class="esc-name">${esc(r.owner)}</span>
            <span style="color:#64748b;font-size:11.5px">${r.this_week}% · ${r.completed}/${r.total}</span>
            <span class="esc-reasons">${r._reasons.map(rs => `<span class="${rs.cls}">${rs.txt}</span>`).join('')}</span>
          </div>`;
        }).join('')}
      </div>
      ${watchlistFull.length > 5 ? `
      <button type="button" class="esc-toggle-btn" onclick="_togglePmoWatchlist()">
        ${_pmoWatchlistExpanded
          ? `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="18 15 12 9 6 15"/></svg> Collapse to top 5`
          : `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg> Show all ${watchlistFull.length} (+${hiddenCount} more)`}
      </button>` : ''}
    </div>` : `
    <div class="pmo-section">
      <div class="pmo-section-title">✓ No Escalations</div>
      <div style="font-size:12.5px;color:#059669;padding:6px 2px">All members operating within tolerance.</div>
    </div>`}
  `;
}

// ── Per-table Copy + Export Image ──────────────────────────────────────────
function _tsvFromRows(rows, mode) {
  if (mode === 'changes') {
    const out = ['Owner\tCompletion Rate\tWeek-over-Week Change'];
    rows.forEach(r => {
      const d = r.delta;
      let chg;
      if (d===null||d===undefined) chg = 'NEW';
      else if (d>0) chg = '+'+d+'%';
      else if (d<0) chg = d+'%';
      else chg = (r.this_week>=100 ? 'Completed' : '0%');
      out.push(`${r.owner}\t${r.this_week}%\t${chg}`);
    });
    return out.join('\n');
  }
  const heads = ['Owner','Total','Open','In Progress','Waiting For Approval','Overdue','Completed','Completion %'];
  const out = [heads.join('\t')];
  rows.forEach(r => {
    if (mode==='this') {
      out.push([r.owner, r.total, r.open, r.in_progress, r.waiting_for_approval,
                r.overdue, r.completed, r.this_week+'%'].join('\t'));
    } else { // last
      const pct = r.last_week!==null&&r.last_week!==undefined ? r.last_week+'%' : '—';
      out.push([r.owner, r.last_total||0, r.last_open||0, r.last_in_progress||0,
                r.last_wfa||0, r.last_overdue||0, r.last_completed||0, pct].join('\t'));
    }
  });
  return out.join('\n');
}

function copyMainTable(mode) {
  const tsv = _tsvFromRows(REPORT.rows, mode);
  navigator.clipboard.writeText(tsv)
    .then(()=>toast('✓ Copied to clipboard — paste into Excel or Outlook.'))
    .catch(e=>toast('Copy failed: '+e.message));
}

function copyRowsTSV(rows, mode) {
  const tsv = _tsvFromRows(rows, mode);
  navigator.clipboard.writeText(tsv)
    .then(()=>toast('✓ Copied to clipboard.'))
    .catch(e=>toast('Copy failed: '+e.message));
}

function copyHistChanges(dateKey) {
  const curr = _HIST_SNAP_CACHE['hist_'+dateKey];
  const prev = _HIST_SNAP_CACHE['prev_'+dateKey];
  if (!curr || !prev) { toast('No previous snapshot to compare.'); return; }
  const cP = curr.people||{}, pP = prev.people||{};
  const names = [...new Set([...Object.keys(cP), ...Object.keys(pP)])].sort();
  const lines = [`Owner\tCompletion %\tChange vs ${prev.date}`];
  names.forEach(n => {
    const cv = cP[n]; const pv = pP[n];
    const cPct = cv ? (typeof cv==='object'?cv.pct:cv) : null;
    const pPct = pv ? (typeof pv==='object'?pv.pct:pv) : null;
    const ch = (cPct!==null && pPct!==null) ? Math.round((cPct-pPct)*10)/10 : null;
    const chTxt = ch===null ? 'NEW' : (ch>0?'+'+ch+'%' : ch+'%');
    lines.push(`${n}\t${cPct!==null?cPct+'%':'—'}\t${chTxt}`);
  });
  navigator.clipboard.writeText(lines.join('\n'))
    .then(()=>toast('✓ Changes copied to clipboard.'))
    .catch(e=>toast('Copy failed: '+e.message));
}

function exportMainTable(mode) {
  // Reuse the canvas exporter, only the selected section
  const secs = {tw: mode==='this', lw: mode==='last', ch: mode==='changes'};
  toast('Generating image…');
  setTimeout(()=>{
    try { _drawCanvas(secs, null, hiddenPeople); }
    catch(e){ toast('Export failed: '+e.message); console.error(e); }
  }, 50);
}

// ───────── Universal canvas → clipboard / download helpers ─────────
// Works on iOS Safari, Android Chrome, and desktop. iOS requires the
// ClipboardItem blob to be passed as a *Promise* initiated synchronously
// in the user-gesture frame — not an already-resolved Blob.
async function _copyCanvasToClipboard(cv, fallbackName) {
  if (!cv) return false;
  try {
    if (!navigator.clipboard || !window.ClipboardItem) throw new Error('Clipboard image API unavailable');
    // Pass a Promise<Blob> so iOS Safari accepts the write inside the gesture.
    const blobPromise = new Promise((resolve, reject) => {
      cv.toBlob(b => b ? resolve(b) : reject(new Error('toBlob returned null')), 'image/png');
    });
    await navigator.clipboard.write([new ClipboardItem({'image/png': blobPromise})]);
    toast('✓ Image copied — paste anywhere.');
    return true;
  } catch (e) {
    console.warn('[copy-image] clipboard failed, falling back to share/download:', e);
    return await _shareOrDownloadCanvas(cv, fallbackName || 'image.png', '✓ Image saved.');
  }
}

// ── Canvas → PNG blob helper ────────────────────────────────────────────────
async function _canvasBlob(cv, filename) {
  const isJpg = /\.jpe?g$/i.test(filename || '');
  const mime  = isJpg ? 'image/jpeg' : 'image/png';
  const blob = await new Promise(res => cv.toBlob(res, mime, isJpg ? 0.92 : undefined));
  return {blob, mime};
}

// Some environments silently drop <a download> clicks (Electron / embedded
// webviews / in-app browsers). Detect those so we fall back to a visible
// "save this image" overlay that works everywhere.
function _downloadLikelyBlocked() {
  const ua = navigator.userAgent || '';
  return /Electron/i.test(ua)            // desktop app webview
      || /\bwv\b|; wv\)/i.test(ua)       // Android WebView
      || /FBAN|FBAV|Instagram|Line\/|Twitter|MicroMessenger/i.test(ua); // in-app browsers
}

// Universal "save image" overlay — shows the rendered image full-size with a
// Download button and right-click / long-press hint. Works in EVERY context
// (real browsers, Electron, mobile) because it relies only on a visible <img>.
function _showImageSaveOverlay(blob, filename) {
  const url = URL.createObjectURL(blob);
  const ov = document.createElement('div');
  ov.style.cssText =
    'position:fixed;inset:0;z-index:99999;background:rgba(15,23,42,.82);' +
    'display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px;gap:14px;backdrop-filter:blur(3px)';
  ov.innerHTML =
    `<div style="color:#fff;font:600 14px -apple-system,Segoe UI,Arial;text-align:center;max-width:520px">
       Right-click the image → <b>Save image as…</b> &nbsp;(or tap Download)
     </div>
     <img src="${url}" style="max-width:92vw;max-height:74vh;border-radius:10px;
       box-shadow:0 12px 40px rgba(0,0,0,.5);background:#fff" alt="${filename}">
     <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:center">
       <a href="${url}" download="${filename}"
          style="background:#2563eb;color:#fff;padding:11px 22px;border-radius:8px;
                 font:700 14px -apple-system,Segoe UI,Arial;text-decoration:none">⬇ Download ${filename}</a>
       <button style="background:#fff;color:#0f172a;padding:11px 22px;border:0;border-radius:8px;
                 font:700 14px -apple-system,Segoe UI,Arial;cursor:pointer">Close</button>
     </div>`;
  const close = () => { ov.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); };
  ov.querySelector('button').onclick = close;
  ov.addEventListener('click', e => { if (e.target === ov) close(); });
  document.body.appendChild(ov);
}

// Save to desktop (Windows / Mac / Linux). Plain anchor download in real
// browsers; falls back to the visible overlay inside Electron / webviews
// where the download click is silently ignored.
async function _shareOrDownloadCanvas(cv, filename, successMsg) {
  if (!cv) return false;
  const {blob} = await _canvasBlob(cv, filename);
  if (!blob) { toast('Could not encode image.'); return false; }

  if (_downloadLikelyBlocked()) {
    _showImageSaveOverlay(blob, filename);
    return true;
  }

  try {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    toast(successMsg || `✓ Downloaded ${filename}.`);
    return true;
  } catch (e) {
    console.warn('[download-image] failed, showing overlay:', e);
    _showImageSaveOverlay(blob, filename);
    return true;
  }
}

// Share to mobile (iOS/Android share sheet → Save to Photos / WhatsApp etc.)
async function _shareCanvasMobile(cv, filename, successMsg) {
  if (!cv) return false;
  const {blob, mime} = await _canvasBlob(cv, filename);
  if (!blob) { toast('Could not encode image.'); return false; }
  // Try Web Share API with files (iOS 15+, Chrome Android)
  try {
    if (navigator.canShare && navigator.share) {
      const file = new File([blob], filename, {type: mime});
      if (navigator.canShare({files: [file]})) {
        await navigator.share({files: [file], title: filename});
        toast(successMsg || '✓ Shared.');
        return true;
      }
    }
  } catch (e) {
    if (e.name !== 'AbortError') console.warn('[share-mobile]', e);
  }
  // Fallback: show the image overlay — long-press → Save Image works on every
  // mobile browser (and window.open is often blocked in webviews anyway).
  _showImageSaveOverlay(blob, filename);
  return true;
}

// Copy the same full-dashboard PNG that the Weekly Export button produces
// to the clipboard. Internally swaps REPORT to the chosen snapshot, captures
// the live DOM via html2canvas, then restores REPORT.
async function copySnapshotImage(currSnap, prevSnap) {
  const cv = await _captureSnapshotAsLiveDashboard(currSnap, prevSnap);
  if (!cv) return;
  await _copyCanvasToClipboard(cv, `progress-${currSnap.date}.png`);
}

// Temporarily swap REPORT to a chosen snapshot, re-render the dashboard,
// capture via the live-DOM path (same look as Weekly Export), then restore.
async function _captureSnapshotAsLiveDashboard(currSnap, prevSnap) {
  const saved = JSON.parse(JSON.stringify({
    rows: REPORT.rows, date: REPORT.date, timestamp: REPORT.timestamp,
    last_snap_date: REPORT.last_snap_date, last_snap_time: REPORT.last_snap_time,
    team_total: REPORT.team_total, team_last_week: REPORT.team_last_week,
    team_delta: REPORT.team_delta, grand_total: REPORT.grand_total, grand_done: REPORT.grand_done,
  }));
  try {
    _applySnapshotToReport(currSnap, prevSnap);
    // Re-render with the swapped data so html2canvas captures it.
    if (typeof renderThisWeek === 'function') {
      const hide = (hiddenPeople && hiddenPeople.size) ? hiddenPeople : null;
      const tw = document.getElementById('tbl-tw');
      const lw = document.getElementById('tbl-lw');
      const ch = document.getElementById('tbl-ch');
      if (tw) tw.innerHTML = renderThisWeek(REPORT.rows, hide);
      if (lw) lw.innerHTML = renderLastWeek(REPORT.rows, hide);
      if (ch) ch.innerHTML = renderChanges(REPORT.rows, hide);
      if (typeof renderDonut === 'function') renderDonut();
      if (typeof renderPMOPanel === 'function') renderPMOPanel();
    }
    // Wait for layout
    await new Promise(r => setTimeout(r, 120));
    // Tables only — same styling/format as the Weekly tab, but no Dashboard
    // panel (stats cards / donut / RAG / KPIs are dashboard-only).
    const secs = {tw:true, lw: !!prevSnap, ch: !!prevSnap, dash:false};
    return await _captureLiveDashboard(secs);
  } catch(e) {
    console.error('[snap-export]', e);
    toast('Render failed: '+e.message);
    return null;
  } finally {
    Object.assign(REPORT, saved);
    if (typeof _rerenderTables === 'function') _rerenderTables();
  }
}

// Mutate REPORT in-place to reflect a chosen historical snapshot.
function _applySnapshotToReport(currSnap, prevSnap) {
  const currPeople = currSnap.people || {};
  const prevPeople = prevSnap ? (prevSnap.people || {}) : {};
  const allNames = [...new Set([...Object.keys(currPeople), ...Object.keys(prevPeople)])]
    .sort((a,b)=>a.toLowerCase().localeCompare(b.toLowerCase()));
  const _val = (v, k, def=0) => {
    if (v === undefined || v === null) return def;
    if (typeof v === 'object') return v[k] !== undefined ? v[k] : def;
    return k === 'pct' ? v : def;
  };
  const newRows = allNames.map(name => {
    const c = currPeople[name];
    const p = prevSnap ? prevPeople[name] : undefined;
    const cPct = c !== undefined ? _val(c, 'pct', 0) : 0;
    const pPct = p !== undefined ? _val(p, 'pct') : null;
    return {
      owner: name,
      total: _val(c, 'total'), open: _val(c, 'open'),
      in_progress: _val(c, 'in_progress'),
      waiting_for_approval: _val(c, 'waiting_for_approval'),
      overdue: _val(c, 'overdue'),
      completed: _val(c, 'completed', _val(c, 'done')),
      this_week: cPct,
      last_week: pPct,
      last_total: _val(p, 'total'), last_open: _val(p, 'open'),
      last_in_progress: _val(p, 'in_progress'),
      last_wfa: _val(p, 'waiting_for_approval'),
      last_overdue: _val(p, 'overdue'),
      last_completed: _val(p, 'completed', _val(p, 'done')),
      delta: pPct !== null && pPct !== undefined ? Math.round((cPct - pPct)*10)/10 : null,
    };
  });
  REPORT.rows = newRows;
  REPORT.date = currSnap.date;
  REPORT.timestamp = currSnap.timestamp || (currSnap.date + 'T09:00:00+00:00');
  REPORT.last_snap_date = prevSnap ? prevSnap.date : null;
  REPORT.last_snap_time = prevSnap ? (prevSnap.timestamp || prevSnap.date) : null;
  REPORT.team_total = currSnap.team_total;
  REPORT.team_last_week = prevSnap ? prevSnap.team_total : null;
  REPORT.team_delta = prevSnap ? Math.round((currSnap.team_total - prevSnap.team_total)*10)/10 : null;
  REPORT.grand_total = newRows.reduce((s,r)=>s+(r.total||0),0);
  REPORT.grand_done  = newRows.reduce((s,r)=>s+(r.completed||0),0);
}

async function exportSnapshotImage(currSnap, prevSnap) {
  const cv = await _captureSnapshotAsLiveDashboard(currSnap, prevSnap);
  if (!cv) return;
  await _shareOrDownloadCanvas(cv, `progress-${currSnap.date}.png`, `✓ Saved progress-${currSnap.date}.png`);
}

// Capture ONLY the .col-block (single table card) the clicked button is in.
// Robust html2canvas wrapper. On mobile, responsive CSS collapses table
// columns / flex children to 0 width, and html2canvas then crashes with
// "createPattern ... width or height of 0" while rendering gradient
// backgrounds. We fix that by forcing the clone to lay out at a desktop
// viewport width so nothing collapses, and by expanding overflow:auto
// scroll containers so the full table is captured (not clipped).
async function _h2c(el, extra = {}) {
  await _ensureHtml2Canvas();
  const DESKTOP_W = 1280;
  const fullW = Math.max(el.scrollWidth || 0, el.offsetWidth || 0, 0);
  const winW  = Math.max(fullW, DESKTOP_W);
  const opts = {
    backgroundColor: '#ffffff',
    scale: 2,
    logging: false,
    useCORS: true,
    letterRendering: true,
    // Force desktop-class layout so mobile media queries don't zero-collapse.
    windowWidth: winW,
    windowHeight: Math.max(el.scrollHeight || 0, el.offsetHeight || 0, 900),
    onclone: (doc) => {
      try {
        const view = doc.defaultView || window;
        doc.querySelectorAll('*').forEach(n => {
          if (!n.style) return;
          const cs = view.getComputedStyle(n);
          if (cs && (cs.overflowX === 'auto' || cs.overflowX === 'scroll' ||
                     cs.overflow === 'auto' || cs.overflow === 'scroll')) {
            n.style.overflow = 'visible';
          }
        });
      } catch (_) { /* best-effort */ }
    },
    ...extra,
  };
  return await html2canvas(el, opts);
}

async function _captureNearestBlock(btn) {
  const block = btn && btn.closest && btn.closest('.col-block');
  if (!block) { toast('Could not find table.'); return null; }
  document.body.classList.add('capturing');
  await new Promise(r => setTimeout(r, 60));
  try {
    return await _h2c(block);
  } finally {
    document.body.classList.remove('capturing');
  }
}

async function exportHistTable(btn, label, mobile) {
  const cv = await _captureNearestBlock(btn);
  if (!cv) return;
  const fn = `${label}.png`;
  mobile ? await _shareCanvasMobile(cv, fn) : await _shareOrDownloadCanvas(cv, fn, `✓ Saved ${fn}`);
}

async function copyDashboardImage(btn) {
  const block = document.getElementById('analytics-card');
  if (!block) { toast('Dashboard not found.'); return; }
  // Make sure the dashboard is expanded for a complete capture; restore after.
  const wasCollapsed = block.classList.contains('collapsed');
  if (wasCollapsed) block.classList.remove('collapsed');
  document.body.classList.add('capturing');
  await new Promise(r => setTimeout(r, 60));
  try {
    const cv = await _h2c(block);
    const blob = await new Promise(res => cv.toBlob(res, 'image/png'));
    if (!navigator.clipboard || !window.ClipboardItem)
      throw new Error('Clipboard image not supported');
    await navigator.clipboard.write([new ClipboardItem({'image/png': blob})]);
    toast('✓ Dashboard image copied — paste anywhere.');
  } catch (e) {
    console.error('[copy-dash]', e);
    toast('Copy failed: '+e.message);
  } finally {
    document.body.classList.remove('capturing');
    if (wasCollapsed) block.classList.add('collapsed');
  }
}

async function copyHistTable(btn) {
  const cv = await _captureNearestBlock(btn);
  if (!cv) return;
  await _copyCanvasToClipboard(cv, 'table.png');
}

// Legacy fallback (manual canvas draw) — kept for reference, no longer wired up.
function _legacyExportSnapshotImage(currSnap, prevSnap) {
  // currSnap = chosen week, prevSnap = previous week (may be null)
  // Renders full dashboard view: This Week (curr) + Last Week (prev) + Changes
  const saved = {
    rows: REPORT.rows, date: REPORT.date, timestamp: REPORT.timestamp,
    last_snap_date: REPORT.last_snap_date, last_snap_time: REPORT.last_snap_time,
    team_total: REPORT.team_total, team_last_week: REPORT.team_last_week,
    team_delta: REPORT.team_delta, grand_total: REPORT.grand_total, grand_done: REPORT.grand_done,
  };

  // Build merged rows: each row has this_week fields from curr + last_* fields from prev
  const currPeople = currSnap.people || {};
  const prevPeople = prevSnap ? (prevSnap.people || {}) : {};
  const allNames = [...new Set([...Object.keys(currPeople), ...Object.keys(prevPeople)])]
    .sort((a,b)=>a.toLowerCase().localeCompare(b.toLowerCase()));

  const _val = (v, k, def=0) => {
    if (v === undefined || v === null) return def;
    if (typeof v === 'object') return v[k] !== undefined ? v[k] : def;
    return k === 'pct' ? v : def;
  };

  const newRows = allNames.map(name => {
    const c = currPeople[name];
    const p = prevSnap ? prevPeople[name] : undefined;
    const cPct = c !== undefined ? _val(c, 'pct', 0) : 0;
    const pPct = p !== undefined ? _val(p, 'pct') : null;
    return {
      owner: name,
      total: _val(c, 'total'), open: _val(c, 'open'),
      in_progress: _val(c, 'in_progress'),
      waiting_for_approval: _val(c, 'waiting_for_approval'),
      overdue: _val(c, 'overdue'),
      completed: _val(c, 'completed', _val(c, 'done')),
      this_week: cPct,
      last_week: pPct,
      last_total: _val(p, 'total'), last_open: _val(p, 'open'),
      last_in_progress: _val(p, 'in_progress'),
      last_wfa: _val(p, 'waiting_for_approval'),
      last_overdue: _val(p, 'overdue'),
      last_completed: _val(p, 'completed', _val(p, 'done')),
      delta: pPct !== null && pPct !== undefined ? Math.round((cPct - pPct)*10)/10 : null,
    };
  });

  REPORT.rows = newRows;
  REPORT.date = currSnap.date;
  REPORT.timestamp = currSnap.timestamp || (currSnap.date + 'T09:00:00+00:00');
  REPORT.last_snap_date = prevSnap ? prevSnap.date : null;
  REPORT.last_snap_time = prevSnap ? (prevSnap.timestamp || prevSnap.date) : null;
  REPORT.team_total = currSnap.team_total;
  REPORT.team_last_week = prevSnap ? prevSnap.team_total : null;
  REPORT.team_delta = prevSnap ? Math.round((currSnap.team_total - prevSnap.team_total)*10)/10 : null;
  REPORT.grand_total = newRows.reduce((s,r)=>s+(r.total||0),0);
  REPORT.grand_done  = newRows.reduce((s,r)=>s+(r.completed||0),0);

  toast(`Generating Week ${currSnap.date} image…`);
  setTimeout(()=>{
    try {
      const secs = {tw:true, lw: !!prevSnap, ch: !!prevSnap, hist:false};
      _drawCanvas(secs, null, null);
    }
    catch(e){ toast('Export failed: '+e.message); console.error(e); }
    finally {
      Object.assign(REPORT, saved);
    }
  }, 60);
}

// ── Analytics: collapse + image export ─────────────────────────────────────
function toggleAnalytics() {
  const card = document.getElementById('analytics-card');
  card.classList.toggle('collapsed');
  const collapsed = card.classList.contains('collapsed');
  document.getElementById('analytics-toggle-txt').textContent = collapsed ? 'Expand' : 'Collapse';
  try { localStorage.setItem('analytics_collapsed', collapsed ? '1' : '0'); } catch(e){}
}
// Restore collapse state
document.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => {
    try {
      if (localStorage.getItem('analytics_collapsed') === '1') {
        const card = document.getElementById('analytics-card');
        if (card) {
          card.classList.add('collapsed');
          const t = document.getElementById('analytics-toggle-txt');
          if (t) t.textContent = 'Expand';
        }
      }
    } catch(e){}
  }, 80);
});

function exportDashboard(mobile) {
  toast('Generating dashboard image…');
  setTimeout(async () => {
    try {
      const cv = _drawDashboardCanvas(true);
      if (!cv) return;
      const fn = `analytics-dashboard-${REPORT.date}.png`;
      mobile ? await _shareCanvasMobile(cv, fn) : await _shareOrDownloadCanvas(cv, fn, '✓ Dashboard image saved.');
    } catch (e) { toast('Export failed: '+e.message); console.error(e); }
  }, 50);
}

function _drawDashboardCanvas(returnCanvas) {
  const rows = REPORT.rows.filter(r => r.owner !== 'Unassigned' && (r.total||0) > 0 && !hiddenPeople.has(r.owner));
  if (!rows.length) { toast('No data to export.'); return; }

  // RAG
  const rag = {green:0, amber:0, red:0};
  rows.forEach(r => {
    const pct = r.this_week||0, ov = r.overdue||0, d = r.delta;
    if (pct >= 80 && ov <= 1) rag.green++;
    else if (pct < 50 || ov >= 4 || (d === 0 && pct < 50)) rag.red++;
    else rag.amber++;
  });
  const ragTotal = rag.green + rag.amber + rag.red;

  // Donut data
  const totals = rows.reduce((acc, r) => {
    acc.open += r.open||0; acc.in_progress += r.in_progress||0;
    acc.wfa += r.waiting_for_approval||0; acc.done += r.completed||0;
    return acc;
  }, {open:0, in_progress:0, wfa:0, done:0});
  const totalTasks = totals.open + totals.in_progress + totals.wfa + totals.done;
  const compPct = totalTasks ? Math.round(totals.done/totalTasks*100) : 0;

  // KPIs
  const gTotal = rows.reduce((s,r)=>s+(r.total||0),0);
  const gDone  = rows.reduce((s,r)=>s+(r.completed||0),0);
  const gIP    = rows.reduce((s,r)=>s+(r.in_progress||0),0);
  const gWFA   = rows.reduce((s,r)=>s+(r.waiting_for_approval||0),0);
  const gOv    = rows.reduce((s,r)=>s+(r.overdue||0),0);
  const completion  = gTotal ? +(gDone/gTotal*100).toFixed(1) : 0;
  const overdueRate = gTotal ? +(gOv/gTotal*100).toFixed(1) : 0;
  const wipRatio    = gTotal ? +(gIP/gTotal*100).toFixed(1) : 0;

  // Watchlist
  const watchlist = rows.slice().map(r => {
    const pct = r.this_week||0, ov = r.overdue||0, d = r.delta;
    const reasons = [];
    if (ov >= 2) reasons.push(`${ov} overdue`);
    if (pct < 50) reasons.push(pct === 0 ? 'no progress' : `only ${pct}%`);
    if (d !== null && d !== undefined && d < -5) reasons.push(`${d}% WoW`);
    const score = ov*15 + Math.max(0,50-pct) + (d<0?Math.abs(d)*2:0);
    return {...r, _reasons: reasons, _score: score};
  }).filter(r => r._reasons.length > 0)
    .sort((a,b) => b._score - a._score).slice(0, 5);

  // Layout
  const SCALE = 2;
  const W = 1320, PAD = 40, COL_GAP = 24;
  const LEFT_W = 340;
  const RIGHT_W = W - PAD*2 - LEFT_W - COL_GAP;
  const TITLE_H = 96;
  const RAG_H = 36, KPI_H = 96, ESC_ROW_H = 38;
  const escSection = 30 + (watchlist.length ? watchlist.length*(ESC_ROW_H+6) : 28);
  const rightH = 28 + RAG_H + 32 + 28 + KPI_H + 24 + escSection;
  const leftH = 280 + 24 + 4*22 + 30;
  const BODY_H = Math.max(leftH, rightH);
  const H = PAD + TITLE_H + BODY_H + 50;

  const cv = document.createElement('canvas');
  cv.width = W*SCALE; cv.height = H*SCALE;
  const c = cv.getContext('2d'); c.scale(SCALE, SCALE);

  // Background
  const bg = c.createLinearGradient(0,0,W,H);
  bg.addColorStop(0,'#dbeafe'); bg.addColorStop(.5,'#f0f6ff'); bg.addColorStop(1,'#f0fdf4');
  c.fillStyle = bg; c.fillRect(0,0,W,H);

  let y = PAD;

  // ── Title ──
  c.fillStyle = '#0f172a'; c.font = 'bold 28px Inter, Arial'; c.textAlign = 'left';
  c.fillText('FIBTMP Analytics Dashboard', PAD, y+30);
  c.fillStyle = '#64748b'; c.font = '13px "JetBrains Mono", monospace';
  c.fillText(`${REPORT.date} ${_nowHM()} · Project Management Office · ${rows.length} members · ${gTotal} tasks`, PAD, y+54);

  // Date badge top-right
  const bText = `${REPORT.date} ${_nowHM()}`;
  c.font = 'bold 14px "JetBrains Mono", monospace';
  const bw = c.measureText(bText).width + 130;
  const bx = W - PAD - bw;
  c.fillStyle = '#dbeafe'; _rr(c, bx, y+4, bw, 44, 10); c.fill();
  c.strokeStyle = '#93c5fd'; c.lineWidth = 1.5; _rr(c, bx, y+4, bw, 44, 10); c.stroke();
  c.fillStyle = '#1e40af'; c.font = 'bold 9.5px Inter, Arial'; c.textAlign = 'left';
  c.fillText('GENERATED', bx+15, y+19);
  c.fillStyle = '#0f172a'; c.font = 'bold 15px "JetBrains Mono", monospace';
  c.fillText(bText, bx+15, y+39);

  y += TITLE_H;

  // ── LEFT: Donut + Legend ──
  const dCx = PAD + LEFT_W/2, dCy = y + 130, dR = 92, dSW = 32;
  let acc = 0;
  const segs = [
    {label:'Completed',   val:totals.done,        color:'#10b981'},
    {label:'In Progress', val:totals.in_progress, color:'#3b82f6'},
    {label:'Waiting',     val:totals.wfa,         color:'#f59e0b'},
    {label:'Open',        val:totals.open,        color:'#94a3b8'},
  ];
  segs.forEach(s => {
    if (s.val <= 0) return;
    const a1 = acc/totalTasks*2*Math.PI - Math.PI/2;
    acc += s.val;
    const a2 = acc/totalTasks*2*Math.PI - Math.PI/2;
    c.fillStyle = s.color; c.beginPath();
    c.arc(dCx, dCy, dR, a1, a2);
    c.arc(dCx, dCy, dR-dSW, a2, a1, true);
    c.closePath(); c.fill();
  });
  c.fillStyle = '#0f172a'; c.font = 'bold 40px Inter, Arial'; c.textAlign = 'center';
  c.fillText(`${compPct}%`, dCx, dCy+8);
  c.fillStyle = '#64748b'; c.font = '13px Inter, Arial';
  c.fillText('Completed', dCx, dCy+30);

  let ly = y + 250;
  segs.forEach(s => {
    if (s.val <= 0) return;
    const lx = PAD + 20;
    c.fillStyle = s.color; _rr(c, lx, ly-9, 12, 12, 3); c.fill();
    c.fillStyle = '#334155'; c.font = '13px Inter, Arial'; c.textAlign = 'left';
    c.fillText(s.label, lx+20, ly);
    c.fillStyle = '#0f172a'; c.font = 'bold 13px "JetBrains Mono", monospace'; c.textAlign = 'right';
    c.fillText(`${s.val}  (${Math.round(s.val/totalTasks*100)}%)`, PAD+LEFT_W-10, ly);
    ly += 22;
  });
  // Total tasks line
  ly += 6;
  c.strokeStyle = '#e2e8f0'; c.lineWidth = 1;
  c.beginPath(); c.moveTo(PAD+20, ly-12); c.lineTo(PAD+LEFT_W-10, ly-12); c.stroke();
  c.fillStyle = '#0f172a'; c.font = 'bold 13px Inter, Arial'; c.textAlign = 'left';
  c.fillText('Total tasks', PAD+20, ly+4);
  c.font = 'bold 13px "JetBrains Mono", monospace'; c.textAlign = 'right';
  c.fillText(String(totalTasks), PAD+LEFT_W-10, ly+4);

  // ── RIGHT column ──
  let rx = PAD + LEFT_W + COL_GAP;
  let ry = y;

  // RAG header
  c.fillStyle = '#475569'; c.font = 'bold 11.5px Inter, Arial'; c.textAlign = 'left';
  c.fillText('RAG STATUS DISTRIBUTION', rx, ry+14); ry += 26;

  // RAG bar
  let cx = rx;
  const drawRagSeg = (count, c1, c2) => {
    if (count <= 0) return;
    const w = Math.round(RIGHT_W * count/ragTotal);
    const grad = c.createLinearGradient(cx, 0, cx+w, 0);
    grad.addColorStop(0, c1); grad.addColorStop(1, c2);
    c.fillStyle = grad; c.fillRect(cx, ry, w, RAG_H);
    c.fillStyle = '#fff'; c.font = 'bold 14px Inter, Arial'; c.textAlign = 'center';
    c.fillText(`${Math.round(count/ragTotal*100)}%`, cx+w/2, ry+RAG_H/2+5);
    cx += w;
  };
  drawRagSeg(rag.green, '#34d399', '#059669');
  drawRagSeg(rag.amber, '#fbbf24', '#d97706');
  drawRagSeg(rag.red,   '#f87171', '#dc2626');
  // Border around RAG bar
  c.strokeStyle = '#cbd5e1'; c.lineWidth = 1; c.strokeRect(rx, ry, RIGHT_W, RAG_H);
  ry += RAG_H + 10;

  // RAG legend
  const legend = [
    {col:'#059669', txt:`${rag.green} Healthy (≥80%, ≤1 overdue)`},
    {col:'#d97706', txt:`${rag.amber} Watch`},
    {col:'#dc2626', txt:`${rag.red} At Risk`},
  ];
  let legX = rx;
  c.font = '12px Inter, Arial';
  legend.forEach(l => {
    c.fillStyle = l.col; c.beginPath(); c.arc(legX+5, ry+5, 5, 0, 2*Math.PI); c.fill();
    c.fillStyle = '#475569'; c.textAlign = 'left';
    c.fillText(l.txt, legX+14, ry+9);
    legX += c.measureText(l.txt).width + 32;
  });
  ry += 28;

  // KPI header
  c.fillStyle = '#475569'; c.font = 'bold 11.5px Inter, Arial';
  c.fillText('KEY PERFORMANCE INDICATORS', rx, ry+14); ry += 22;

  // KPI tiles (4 across)
  const kpiW = (RIGHT_W - 24) / 4;
  const kpis = [
    {lbl:'COMPLETION', val:`${completion}%`, sub:`${gDone} / ${gTotal} tasks`,
     col: completion>=80?'#059669':completion>=50?'#d97706':'#dc2626'},
    {lbl:'OVERDUE RATE', val:`${overdueRate}%`, sub:`${gOv} of ${gTotal} past due`,
     col: overdueRate<=5?'#059669':overdueRate<=15?'#d97706':'#dc2626'},
    {lbl:'WIP RATIO', val:`${wipRatio}%`, sub:`${gIP} in progress`,
     col: wipRatio<=20?'#059669':wipRatio<=35?'#d97706':'#dc2626'},
    {lbl:'APPROVAL QUEUE', val:String(gWFA), sub:'waiting for sign-off',
     col: gWFA<=3?'#059669':gWFA<=8?'#d97706':'#dc2626'},
  ];
  kpis.forEach((k, i) => {
    const kx = rx + i*(kpiW+8);
    c.fillStyle = '#ffffff'; _rr(c, kx, ry, kpiW, KPI_H, 10); c.fill();
    c.strokeStyle = '#e2e8f0'; c.lineWidth = 1.5; _rr(c, kx, ry, kpiW, KPI_H, 10); c.stroke();
    c.fillStyle = '#94a3b8'; c.font = 'bold 10px Inter, Arial'; c.textAlign = 'left';
    c.fillText(k.lbl, kx+14, ry+22);
    c.fillStyle = k.col; c.font = 'bold 28px "JetBrains Mono", monospace';
    c.fillText(k.val, kx+14, ry+58);
    c.fillStyle = '#94a3b8'; c.font = '11px Inter, Arial';
    c.fillText(k.sub, kx+14, ry+82);
  });
  ry += KPI_H + 20;

  // Escalation header
  c.fillStyle = '#475569'; c.font = 'bold 11.5px Inter, Arial';
  c.fillText('ESCALATION WATCHLIST (PM ACTION REQUIRED)', rx, ry+14); ry += 24;

  if (watchlist.length === 0) {
    c.fillStyle = '#059669'; c.font = '13px Inter, Arial';
    c.fillText('✓ No escalations — all members operating within tolerance.', rx, ry+18);
  } else {
    watchlist.forEach((r, i) => {
      c.fillStyle = '#ffffff'; _rr(c, rx, ry, RIGHT_W, ESC_ROW_H-2, 6); c.fill();
      c.strokeStyle = '#e2e8f0'; c.lineWidth = 1; _rr(c, rx, ry, RIGHT_W, ESC_ROW_H-2, 6); c.stroke();
      c.fillStyle = '#dc2626'; c.fillRect(rx, ry, 4, ESC_ROW_H-2);

      c.fillStyle = '#94a3b8'; c.font = 'bold 11px "JetBrains Mono", monospace'; c.textAlign = 'left';
      c.fillText(`#${i+1}`, rx+14, ry+22);
      c.fillStyle = '#0f172a'; c.font = 'bold 13.5px Inter, Arial';
      c.fillText(r.owner, rx+46, ry+22);
      c.fillStyle = '#64748b'; c.font = '12px "JetBrains Mono", monospace';
      const nameW = c.measureText(r.owner).width;
      c.font = '12px "JetBrains Mono", monospace';
      c.fillText(`${r.this_week}%  ·  ${r.completed}/${r.total}`, rx+60+nameW, ry+22);

      // Reason chips on right
      let chipX = rx + RIGHT_W - 12;
      r._reasons.slice().reverse().forEach(reason => {
        c.font = 'bold 11px Inter, Arial';
        const tw = c.measureText(reason).width + 16;
        chipX -= tw + 6;
        c.fillStyle = '#fee2e2'; _rr(c, chipX, ry+9, tw, 18, 4); c.fill();
        c.fillStyle = '#991b1b'; c.textAlign = 'center';
        c.fillText(reason, chipX+tw/2, ry+22);
      });
      ry += ESC_ROW_H + 4;
    });
  }

  // Footer
  c.fillStyle = '#94a3b8'; c.font = '11px "JetBrains Mono", monospace'; c.textAlign = 'left';
  c.fillText(`Generated ${REPORT.date} ${_nowHM()} · FIBTMP PMO Health Dashboard`, PAD, H-22);

  if (returnCanvas) return cv;
  _shareOrDownloadCanvas(cv, `analytics-dashboard-${REPORT.date}.png`, '✓ Dashboard image saved.');
}

// ── tab switching ──────────────────────────────────────────────────────────
let currentTab = 'weekly';
function showTab(id, btn) {
  currentTab = id;
  document.getElementById('tab-weekly').style.display = id==='weekly' ? '' : 'none';
  document.getElementById('tab-hist').style.display   = id==='hist'   ? '' : 'none';
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  document.getElementById('range-wrap').style.display = id==='hist' ? '' : 'none';
  applyFilter(document.getElementById('name-filter').value);
}

// ── name filter ────────────────────────────────────────────────────────────
// Recompute the TOTAL row of a snapshot table from the visible data-rows so
// the totals reflect the active filter (not the original full-team sums).
function _recomputeSnapshotTotal(tbl) {
  if (!tbl) return;
  const totRow = tbl.querySelector('tr.total-row');
  if (!totRow) return;
  const cells = totRow.querySelectorAll('td');
  // Layout: [TOTAL, total, open, ip, wfa, overdue, completed, pct, bar]
  if (cells.length < 9) return;
  let sT=0,sO=0,sI=0,sW=0,sOv=0,sC=0;
  tbl.querySelectorAll('tr.data-row').forEach(r => {
    if (r.style.display === 'none') return;
    const c = r.querySelectorAll('td');
    const num = i => parseInt((c[i]?.textContent||'').replace(/[^\d-]/g,''),10) || 0;
    sT  += num(1); sO  += num(2); sI  += num(3);
    sW  += num(4); sOv += num(5); sC  += num(6);
  });
  const pct = sT ? Math.round(1000*sC/sT)/10 : 0;
  cells[1].textContent = sT;
  cells[2].textContent = sO;
  cells[3].textContent = sI;
  cells[4].textContent = sW;
  cells[5].innerHTML   = sOv>0 ? `<span class="ov-badge">${sOv}</span>` : '0';
  cells[6].textContent = sC;
  cells[7].textContent = `${pct}%`;
  const bar = cells[8].querySelector('.bar-fill');
  if (bar) bar.style.width = Math.min(100,pct) + '%';
}

// Hide the team-total row of Changes-style tables (delta tables) when a
// filter is active — the original team delta is no longer meaningful for
// a single-person view.
function _toggleChangesTotal(tbl, filtered) {
  if (!tbl) return;
  const totRow = tbl.querySelector('tr.total-row');
  if (totRow) totRow.style.display = filtered ? 'none' : '';
}

function applyFilter(val) {
  const q = (val||'').toLowerCase().trim();
  document.getElementById('clear-btn').classList.toggle('show', !!q);
  let shown=0, total=0;

  const filterRows = (tbl, countIt) => {
    if (!tbl) return;
    tbl.querySelectorAll('tr.data-row').forEach(row => {
      const name = (row.dataset.owner||'').toLowerCase();
      const match = !q || name.includes(q);
      row.style.display = match ? '' : 'none';
      if (countIt) { if (match) shown++; total++; }
    });
  };

  if (currentTab==='weekly') {
    const tw = document.getElementById('tbl-tw');
    const lw = document.getElementById('tbl-lw');
    const ch = document.getElementById('tbl-ch');
    filterRows(tw, true);
    filterRows(lw, false);
    filterRows(ch, false);
    // Recompute snapshot totals; hide changes total when filtered
    [tw, lw].forEach(wrap => wrap && wrap.querySelectorAll('table').forEach(_recomputeSnapshotTotal));
    if (ch) ch.querySelectorAll('table').forEach(t => _toggleChangesTotal(t, !!q));
  } else {
    const wrap = document.getElementById('tbl-hist');
    if (wrap) {
      filterRows(wrap, true);
      // Each snapshot block has its own table; recompute each independently.
      // Snapshot tables have a TOTAL row with 9 cells → recompute.
      // Changes tables have a 3-cell TEAM TOTAL row → hide when filtered.
      wrap.querySelectorAll('table').forEach(t => {
        const totRow = t.querySelector('tr.total-row');
        if (!totRow) return;
        if (totRow.querySelectorAll('td').length >= 9) _recomputeSnapshotTotal(t);
        else _toggleChangesTotal(t, !!q);
      });
    }
  }
  const cnt = document.getElementById('filter-count');
  if (cnt) cnt.textContent = q ? `${shown} of ${total} members` : `${total} members`;
}
function clearFilter() {
  document.getElementById('name-filter').value = '';
  applyFilter('');
}
function filterToName(name) {
  document.getElementById('name-filter').value = name;
  applyFilter(name);
  openPersonModal(name);
}

// ── Activity Log modal: every recent change, who/what/when ─────────────────
// On-demand live activity feed (changelog for recently-updated issues), loaded
// via the Worker 'activity' action ONLY when the Activity Log opens - never on
// the every-10s live path, so it can't blow the Worker CPU budget.
let _ACTIVITY_OVERLAY = null;
async function _loadActivityFeed(days){
  if(!GH_PROXY) return;
  const pw = sessionStorage.getItem('pw_cache')||'';
  try{
    const r = await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw},body:JSON.stringify({action:'activity',days:days||7})});
    if(!r.ok) return;
    const d = await r.json();
    const interesting = new Set(['status','duedate','assignee','priority']);
    const out=[];
    (d.issues||[]).forEach(it=>{
      const f = it.fields||{};
      const owner = (f.assignee && f.assignee.displayName) || 'Unassigned';
      const summary = f.summary || '';
      const hist = (it.changelog && it.changelog.histories) || [];
      hist.forEach(h=>{
        const when=h.created; if(!when) return;
        const author=(h.author && h.author.displayName) || 'Unknown';
        (h.items||[]).forEach(item=>{
          const field=(item.field||'').toLowerCase();
          if(!interesting.has(field)) return;
          out.push({when, author, field, from:item.fromString||'', to:item.toString||'', key:it.key, summary, owner, _t:new Date(when).getTime()});
        });
      });
    });
    out.sort((a,b)=>b._t-a._t);
    _ACTIVITY_OVERLAY = out;
  }catch(e){}
}
function _collectActivity() {
  const hide = (hiddenPeople && hiddenPeople.size) ? hiddenPeople : null;
  // Prefer the live activity feed when loaded; else fall back to REPORT events.
  if (_ACTIVITY_OVERLAY && _ACTIVITY_OVERLAY.length) {
    return _ACTIVITY_OVERLAY.filter(e => !(hide && hide.has(e.owner)));
  }
  const out = [];
  (REPORT.rows || []).forEach(r => {
    if (hide && hide.has(r.owner)) return;
    (r.issues || []).forEach(i => {
      (i.events || []).forEach(e => {
        out.push({...e, key: i.key, summary: i.summary, owner: r.owner, _t: new Date(e.when).getTime()});
      });
    });
  });
  return out.sort((a,b) => b._t - a._t);
}

// Gate for the Admin link. The password is NEVER stored in this page — it is
// verified SERVER-SIDE by the Worker proxy (its ADMIN_PASSWORD secret).
let _RESTRICTED_OK = false;
// Returns true (admin password) / false (wrong) / null (proxy unreachable).
async function _verifyRestrictedServerSide(pw) {
  if (!GH_PROXY) return null;
  try {
    const r = await fetch(GH_PROXY, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Proxy-Auth': pw },
      body: JSON.stringify({ action: 'verify' })
    });
    if (r.status !== 200) return false;
    const d = await r.json();
    return d.role === 'admin';
  } catch (e) { return null; }
}
function _ensureRestrictedModal() {
  if (document.getElementById('rgate-overlay')) return;
  const wrap = document.createElement('div');
  wrap.id = 'rgate-overlay';
  wrap.style.cssText = 'position:fixed;inset:0;background:rgba(15,23,42,.55);backdrop-filter:blur(6px);display:none;align-items:center;justify-content:center;z-index:9999;font-family:Inter,system-ui,sans-serif';
  wrap.innerHTML = `
    <div style="background:#fff;border-radius:16px;padding:26px 28px;width:min(360px,92vw);box-shadow:0 20px 60px rgba(15,23,42,.3)">
      <div style="font-weight:800;font-size:17px;margin-bottom:4px;color:#0f172a">Restricted</div>
      <div style="color:#64748b;font-size:13px;margin-bottom:14px">Enter password to continue.</div>
      <input id="rgate-inp" type="password" autocomplete="off"
        style="width:100%;border:1.5px solid #e2e8f0;border-radius:10px;padding:10px 12px;font-size:14px;outline:none;font-family:inherit"/>
      <div id="rgate-err" style="color:#dc2626;font-size:12px;margin-top:6px;height:14px"></div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px">
        <button id="rgate-cancel" style="border:1px solid #e2e8f0;background:#fff;border-radius:8px;padding:8px 14px;font-weight:600;cursor:pointer">Cancel</button>
        <button id="rgate-ok" style="border:none;background:#0f9389;color:#fff;border-radius:8px;padding:8px 16px;font-weight:700;cursor:pointer">OK</button>
      </div>
    </div>`;
  document.body.appendChild(wrap);
}
function _askRestrictedPw() {
  return new Promise(resolve => {
    _ensureRestrictedModal();
    const ov = document.getElementById('rgate-overlay');
    const inp = document.getElementById('rgate-inp');
    const err = document.getElementById('rgate-err');
    err.textContent = '';
    inp.value = '';
    ov.style.display = 'flex';
    setTimeout(() => inp.focus(), 30);
    const cleanup = () => { ov.style.display = 'none'; inp.onkeydown = null; };
    const submit = async () => {
      const val = inp.value;
      if (!val) { err.textContent = 'Enter the password.'; return; }
      err.textContent = 'Checking…';
      const ok = await _verifyRestrictedServerSide(val);
      if (ok) { _RESTRICTED_OK = true; cleanup(); resolve(true); }
      else { err.textContent = ok === null ? 'Cannot reach server.' : 'Incorrect.'; inp.select(); }
    };
    document.getElementById('rgate-ok').onclick = submit;
    document.getElementById('rgate-cancel').onclick = () => { cleanup(); resolve(false); };
    inp.onkeydown = e => {
      if (e.key === 'Enter') submit();
      else if (e.key === 'Escape') { cleanup(); resolve(false); }
    };
  });
}
async function gateAdmin(ev) {
  if (_RESTRICTED_OK) return true;
  ev.preventDefault();
  const target = ev.currentTarget;
  const ok = await _askRestrictedPw();
  if (!ok) return false;
  const url = target.dataset?.url || target.getAttribute('href');
  if (url) window.open(url, '_blank', 'noopener');
  return false;
}

async function openActivityModal() {
  if (!REPORT) return;
  openModal('activity-modal');
  const list = document.getElementById('act-list');
  if (list && !(_ACTIVITY_OVERLAY && _ACTIVITY_OVERLAY.length))
    list.innerHTML = '<div class="act-empty" style="padding:28px;text-align:center;color:#94a3b8">Loading recent activity...</div>';
  await _loadActivityFeed(7);
  _renderActivityList();
}

function _renderActivityList() {
  const list = document.getElementById('act-list');
  if (!list) return;
  const base = (REPORT.jira_base_url || 'https://fibtask.atlassian.net').replace(/\/+$/,'');
  const q = (document.getElementById('act-search')?.value || '').toLowerCase().trim();
  const field = document.getElementById('act-field')?.value || '';
  const days = parseInt(document.getElementById('act-range')?.value || '1', 10);
  const horizon = Date.now() - days*86400000;

  let events = _collectActivity().filter(e => e._t >= horizon);
  if (field) events = events.filter(e => e.field === field);
  if (q) {
    events = events.filter(e =>
      (e.author||'').toLowerCase().includes(q) ||
      (e.key||'').toLowerCase().includes(q)    ||
      (e.summary||'').toLowerCase().includes(q)||
      (e.owner||'').toLowerCase().includes(q)  ||
      (e.from||'').toLowerCase().includes(q)   ||
      (e.to||'').toLowerCase().includes(q)
    );
  }

  document.getElementById('act-sub').textContent =
    `${events.length} change(s) · last ${days} day${days===1?'':'s'}`;

  if (!events.length) {
    list.innerHTML = '<div class="act-empty">No changes match these filters.</div>';
    return;
  }

  const ago = ms => {
    const s = Math.max(0, Math.floor((Date.now()-ms)/1000));
    if (s < 60)   return `${s}s ago`;
    const m = Math.floor(s/60);
    if (m < 60)   return `${m}m ago`;
    const h = Math.floor(m/60);
    if (h < 24)   return `${h}h ago`;
    return `${Math.floor(h/24)}d ago`;
  };
  const fmtVal = v => v ? esc(String(v).length > 30 ? v.slice(0,28)+'…' : v) : '<em>none</em>';

  list.innerHTML = events.slice(0, 500).map(e => `
    <div class="act-row">
      <div class="act-when" title="${esc(e.when)}">${ago(e._t)}</div>
      <div class="act-author" title="${esc(e.author)}">${esc(e.author)}</div>
      <div class="act-field ${esc(e.field)}">${esc(e.field)}</div>
      <div class="act-change">
        <span class="act-from">${fmtVal(e.from)}</span><span class="act-arrow">→</span><span class="act-to">${fmtVal(e.to)}</span>
        <div class="act-summary">${esc(e.summary || '')} · owned by ${esc(e.owner)}</div>
      </div>
      <a class="act-key" href="${base}/browse/${encodeURIComponent(e.key)}" target="_blank" rel="noopener">${esc(e.key)} ↗</a>
    </div>
  `).join('');
}

// ── Breaking-news ticker: recently changed tasks across the team ───────────
function _renderBreakingTicker() {
  const bar   = document.getElementById('ticker-bar');
  const strip = document.getElementById('ticker-strip');
  if (!bar || !strip || !REPORT) return;
  const hide = (hiddenPeople && hiddenPeople.size) ? hiddenPeople : null;
  const base = (REPORT.jira_base_url || 'https://fibtask.atlassian.net').replace(/\/+$/,'');

  // Collect issues with a `changed` timestamp; cap to the most recent 25
  // events within the last 24 hours so the strip only shows today's news.
  const horizon = Date.now() - 24*3600*1000;
  const events = [];
  (REPORT.rows || []).forEach(r => {
    if (hide && hide.has(r.owner)) return;
    (r.issues || []).forEach(i => {
      if (!i.changed) return;
      const t = new Date(i.changed).getTime();
      if (isNaN(t) || t < horizon) return;
      events.push({...i, owner: r.owner, _t: t});
    });
  });
  events.sort((a,b) => b._t - a._t);
  const recent = events.slice(0, 25);
  const cntEl = document.getElementById('ticker-count');
  if (cntEl) cntEl.textContent = events.length;
  // The Breaking bar only appears when there are task changes in the last 24h.
  // Activity Log lives in the action button row, so it stays available even
  // when this bar is hidden.
  if (!recent.length) { bar.classList.remove('show'); strip.innerHTML = ''; return; }
  bar.classList.add('show');

  const ago = ms => {
    const s = Math.max(0, Math.floor((Date.now()-ms)/1000));
    if (s < 60)   return `${s}s ago`;
    const m = Math.floor(s/60);
    if (m < 60)   return `${m}m ago`;
    const h = Math.floor(m/60);
    if (h < 24)   return `${h}h ago`;
    return `${Math.floor(h/24)}d ago`;
  };
  const statusClass = s => {
    const n = (s||'').toLowerCase();
    if (/(done|closed|resolv|complete|available)/.test(n)) return 'st-done';
    if (/progress/.test(n)) return 'st-progress';
    if (/(wait|approv|review)/.test(n)) return 'st-wait';
    if (/(hold|block|pause)/.test(n)) return 'st-hold';
    return '';
  };
  const renderOne = (i, idx) => {
    const url = `${base}/browse/${encodeURIComponent(i.key)}`;
    const sum = (i.summary||'').length > 60
      ? i.summary.slice(0,57) + '…'
      : (i.summary || '(no summary)');
    const transition = i.status_from
      ? `<span class="ticker-status ${statusClass(i.status_from)}">${esc(i.status_from)}</span>
         <span class="ticker-arrow">→</span>
         <span class="ticker-status ${statusClass(i.status)}">${esc(i.status)}</span>`
      : `<span class="ticker-status ${statusClass(i.status)}">${esc(i.status)}</span>`;
    return `<a class="ticker-item" href="${url}" target="_blank" rel="noopener" title="Open ${esc(i.key)} in Jira">
      <span class="ticker-num">${idx + 1}</span>
      <span class="ticker-key">${esc(i.key)}</span>
      <span>${esc(sum)}</span>
      <span class="ticker-arrow">→</span>
      ${transition}
      <span class="ticker-owner">${esc(i.owner)}</span>
      <span class="ticker-time">${ago(i._t)}</span>
    </a><span class="ticker-sep">•</span>`;
  };
  const html = recent.map(renderOne).join('');
  if (recent.length === 1) {
    // Single item — show statically, no scroll
    strip.innerHTML = html;
    strip.style.animation = 'none';
  } else {
    // Duplicate so the CSS loop is seamless (translates 0 → -50%)
    strip.innerHTML = html + html;
    strip.style.animation = '';
    // Keep the scroll SPEED constant regardless of how many items are in the
    // strip. The CSS animation translates by a fixed -50% (one copy's width),
    // so a fixed duration would scroll faster as more items are added. Instead
    // we derive the duration from the actual pixel distance at a fixed speed.
    const PX_PER_SEC = 50;  // scroll speed — higher = faster. Tune this only.
    requestAnimationFrame(() => {
      const oneCopyPx = strip.scrollWidth / 2;  // distance of a single -50% loop
      if (oneCopyPx > 0) {
        const dur = Math.max(8, oneCopyPx / PX_PER_SEC);  // seconds, floor at 8s
        strip.style.animationDuration = dur.toFixed(1) + 's';
      }
    });
  }
}

// ── Overdue tasks modal (all owners, sorted by most-overdue first) ─────────
function _refreshOverdueBadge() {
  const btn   = document.getElementById('overdue-btn');
  const count = document.getElementById('overdue-count');
  if (!btn || !count || !REPORT) return;
  const hide = (hiddenPeople && hiddenPeople.size) ? hiddenPeople : null;
  const items = _collectOverdue(hide);
  if (items.length) {
    btn.style.display = '';
    count.textContent = items.length;
  } else {
    btn.style.display = 'none';
  }
}
function _collectOverdue(hide) {
  const out = [];
  (REPORT.rows || []).forEach(r => {
    if (hide && hide.has(r.owner)) return;
    (r.issues || []).forEach(i => { if (i.overdue) out.push({...i, owner: r.owner}); });
  });
  // Most overdue (oldest due) first
  out.sort((a,b) => (a.due||'') < (b.due||'') ? -1 : 1);
  return out;
}
function openOverdueModal() {
  if (!REPORT) return;
  const hide = (hiddenPeople && hiddenPeople.size) ? hiddenPeople : null;
  const items = _collectOverdue(hide);
  const base = (REPORT.jira_base_url || 'https://fibtask.atlassian.net').replace(/\/+$/,'');

  const fmtAgo = isoOrDate => {
    if (!isoOrDate) return '';
    const d = new Date(String(isoOrDate).length <= 10 ? isoOrDate + 'T00:00:00Z' : isoOrDate);
    if (isNaN(d.getTime())) return '';
    const days = Math.max(0, Math.floor((Date.now() - d.getTime()) / 86400000));
    if (days === 0) return 'today';
    if (days === 1) return '1 day ago';
    if (days < 30)  return `${days} days ago`;
    const months = Math.round(days/30);
    if (months < 12) return `${months} month${months===1?'':'s'} ago`;
    const years = Math.round(days/365);
    return `${years} year${years===1?'':'s'} ago`;
  };
  const statusClass = s => {
    const n = (s||'').toLowerCase();
    if (/(done|closed|resolv|complete|available)/.test(n)) return 'st-done';
    if (/progress/.test(n)) return 'st-progress';
    if (/(wait|approv|review)/.test(n)) return 'st-wait';
    if (/(hold|block|pause)/.test(n)) return 'st-hold';
    return 'st-open';
  };

  // Use the same grouped rich-HTML for the in-modal preview so what the
  // user sees is exactly what gets copied/exported.
  document.getElementById('ov-sub').textContent =
    `${items.length} task(s) past due · grouped by owner · click any row to open in Jira`;
  document.getElementById('ov-body').innerHTML =
    items.length ? _buildOverdueRichHTML()
                 : '<div class="empty" style="padding:30px">No overdue tasks. 🎉</div>';
  openModal('overdue-modal');
}

// ── Comment-on-overdue ─────────────────────────────────────────────────────
// Normalise a Jira issue type to a coarse bucket for the type filter.
function _typeBucket(t) {
  const n = (t || '').toLowerCase();
  if (n.includes('sub'))   return 'Sub-task';
  if (n.includes('epic'))  return 'Epic';
  if (n.includes('story')) return 'Story';
  if (n.includes('bug'))   return 'Bug';
  if (n.includes('task'))  return 'Task';
  return t || 'Other';
}

function openCommentModal() {
  if (!REPORT) return;
  const hide = (hiddenPeople && hiddenPeople.size) ? hiddenPeople : null;
  const items = _collectOverdue(hide);
  if (!items.length) { toast('No overdue tasks to comment on. 🎉'); return; }

  // Stash on the modal so render/post read the live selection state.
  _CM_ITEMS = items.map((i, idx) => ({
    idx,
    key: i.key,
    summary: i.summary || '',
    owner: i.owner || '',
    assignee_id: i.assignee_id || '',
    type: i.type || '',
    bucket: _typeBucket(i.type),
    is_subtask: !!i.is_subtask,
    checked: true,
  }));

  // Build the type-filter chips from the buckets actually present.
  const buckets = [...new Set(_CM_ITEMS.map(i => i.bucket))].sort();
  _CM_TYPES = new Set(buckets);          // all on by default
  const tdiv = document.getElementById('cm-types');
  tdiv.innerHTML = buckets.map(b => {
    const count = _CM_ITEMS.filter(i => i.bucket === b).length;
    return `<label class="cm-type-chip" style="display:inline-flex;align-items:center;gap:5px;padding:5px 11px;border:1px solid #cbd5e1;border-radius:999px;font-size:12px;font-weight:700;color:#334155;cursor:pointer;user-select:none">
      <input type="checkbox" checked onchange="cmToggleType('${esc(b)}',this.checked)" style="margin:0">
      ${esc(b)} <span style="color:#94a3b8;font-weight:600">${count}</span>
    </label>`;
  }).join('');

  // Build the people-filter chips from the owners actually present.
  const people = [...new Set(_CM_ITEMS.map(i => i.owner))].sort((a,b)=>a.localeCompare(b));
  _CM_PEOPLE = new Set(people);          // everyone on by default
  const pdiv = document.getElementById('cm-people');
  pdiv.innerHTML = people.map(p => {
    const count = _CM_ITEMS.filter(i => i.owner === p).length;
    const label = p || 'Unassigned';
    return `<label class="cm-type-chip" style="display:inline-flex;align-items:center;gap:5px;padding:5px 11px;border:1px solid #cbd5e1;border-radius:999px;font-size:12px;font-weight:700;color:#334155;cursor:pointer;user-select:none">
      <input type="checkbox" checked onchange="cmTogglePerson('${esc(p).replace(/'/g,"\\'")}',this.checked)" style="margin:0">
      ${esc(label)} <span style="color:#94a3b8;font-weight:600">${count}</span>
    </label>`;
  }).join('');

  // Prefill CC from the saved recipients sheet (user can edit/clear).
  const cc = document.getElementById('cm-cc');
  if (cc && !cc.value) {
    cc.value = (Array.isArray(SAVED_EMAILS) ? SAVED_EMAILS : []).join(', ');
  }

  cmRenderList();
  openModal('comment-modal');
}

function cmToggleType(bucket, on) {
  if (on) _CM_TYPES.add(bucket); else _CM_TYPES.delete(bucket);
  // Auto (un)check items of this type to match the filter.
  _CM_ITEMS.forEach(i => { if (i.bucket === bucket) i.checked = on; });
  cmRenderList();
}

function cmTogglePerson(owner, on) {
  if (on) _CM_PEOPLE.add(owner); else _CM_PEOPLE.delete(owner);
  // Hidden people's tasks vanish from the list and never get a comment.
  _CM_ITEMS.forEach(i => { if (i.owner === owner) i.checked = on; });
  cmRenderList();
}

function cmSetPeople(on) {
  _CM_ITEMS.forEach(i => {
    if (on) _CM_PEOPLE.add(i.owner); else _CM_PEOPLE.delete(i.owner);
  });
  // Reflect on the chip checkboxes.
  document.querySelectorAll('#cm-people input[type=checkbox]').forEach(cb => cb.checked = on);
  cmRenderList();
}

function cmSetAll(on) {
  _CM_ITEMS.forEach(i => { if (_cmVisible(i)) i.checked = on; });
  cmRenderList();
}

function cmRenderList() {
  const base = (REPORT.jira_base_url || 'https://fibtask.atlassian.net').replace(/\/+$/,'');
  const visible = _CM_ITEMS.filter(_cmVisible);
  const list = document.getElementById('cm-list');
  list.innerHTML = visible.length ? visible.map(i => {
    const url = `${base}/browse/${encodeURIComponent(i.key)}`;
    const sum = i.summary.length > 70 ? i.summary.slice(0,67) + '…' : (i.summary || '(no summary)');
    return `<label style="display:flex;gap:9px;align-items:flex-start;padding:8px 11px;border-bottom:1px solid #f1f5f9;cursor:pointer">
      <input type="checkbox" ${i.checked ? 'checked' : ''} onchange="cmToggle(${i.idx},this.checked)" style="margin-top:2px">
      <span style="flex:1;min-width:0">
        <span style="font-family:'JetBrains Mono',Consolas,monospace;font-size:12px;font-weight:700;color:#1e40af">${esc(i.key)}</span>
        <span style="display:inline-block;margin-left:6px;font-size:10px;font-weight:700;color:#475569;background:#eef2ff;padding:1px 6px;border-radius:999px">${esc(i.bucket)}</span>
        <span style="display:block;font-size:12.5px;color:#0f172a;margin-top:1px">${esc(sum)}</span>
        <span style="display:block;font-size:11px;color:#64748b">@${esc(i.owner)}${i.assignee_id ? '' : ' · no accountId (mention resolved by name)'}</span>
      </span>
      <a href="${url}" target="_blank" rel="noopener" onclick="event.stopPropagation()" style="font-size:11px;color:#2563eb;text-decoration:none">open ↗</a>
    </label>`;
  }).join('') : '<div style="padding:20px;text-align:center;color:#94a3b8;font-size:12.5px">No issues match the selected types.</div>';
  cmRecount();
}

function cmToggle(idx, on) {
  const it = _CM_ITEMS.find(i => i.idx === idx);
  if (it) it.checked = on;
  cmRecount();
}

function cmRecount() {
  const n = _CM_ITEMS.filter(i => i.checked && _cmVisible(i)).length;
  document.getElementById('cm-count').textContent = n;
  document.getElementById('cm-post-btn').disabled = (n === 0);
}

let _CM_ITEMS = [];
let _CM_TYPES = new Set();
let _CM_PEOPLE = new Set();   // owners currently included (filterable)

// An item shows / counts only if BOTH its type and its owner are included.
function _cmVisible(i) {
  return _CM_TYPES.has(i.bucket) && _CM_PEOPLE.has(i.owner);
}

async function cancelQueue() {
  const repo = document.querySelector('meta[name=repo]')?.content || '';
  if (!repo)   { toast('Repo not configured.'); return; }
  if (!GH_PAT) { toast('No token — re-enter password.'); return; }
  if (!confirm('Cancel the queued comment batch?\n\nComments not yet posted will be discarded, and any in-progress comment run will be stopped.')) return;
  const btn = document.getElementById('cm-cancel-btn');
  const status = document.getElementById('cm-status');
  if (btn) btn.disabled = true;
  if (status) status.textContent = 'Cancelling…';
  // 1) Empty the queue (retry-safe) so nothing pending will post.
  const cleared = await _saveEncStore('comment_queue.json', { items: [] }, 'Cancel queued comments');
  // 2) Stop any in-progress / queued comment runs.
  let stopped = 0;
  try {
    const hdrs = { 'Authorization':`Bearer ${GH_PAT}`, 'Accept':'application/vnd.github+json' };
    for (const st of ['in_progress','queued']) {
      const r = await fetch(`https://api.github.com/repos/${repo}/actions/workflows/comments.yml/runs?status=${st}&per_page=30`, { headers: hdrs });
      if (!r.ok) continue;
      const d = await r.json();
      for (const run of (d.workflow_runs || [])) {
        const c = await fetch(`https://api.github.com/repos/${repo}/actions/runs/${run.id}/cancel`, { method:'POST', headers: hdrs });
        if (c.ok) stopped++;
      }
    }
  } catch(e) {}
  if (btn) btn.disabled = false;
  if (status) status.textContent = '';
  toast(cleared ? `Queue cancelled${stopped ? ` · stopped ${stopped} run(s)` : ''}.` : 'Could not clear queue — try again.');
}

async function postComments() {
  const repo = document.querySelector('meta[name=repo]')?.content || '';
  if (!GH_PAT) { toast('No token — re-enter password.'); return; }
  if (!repo)   { toast('Repo not configured.'); return; }

  const chosen = _CM_ITEMS.filter(i => i.checked && _cmVisible(i));
  if (!chosen.length) { toast('Select at least one issue.'); return; }

  // Require the admin password before any Jira comment is queued/posted.
  const pw = prompt('Enter the admin password to post comments to Jira:');
  if (pw === null) return;            // user cancelled
  if (!pw) { toast('Password required — comments not posted.'); return; }
  // The password is NOT checked here — it's verified server-side by the Worker.
  // That keeps the real password out of this page's source. A wrong password
  // simply makes the Worker reject the comment write with a 401.
  window.__COMMENT_PW = pw;

  const template = document.getElementById('cm-template').value || '';
  const cc_emails = (document.getElementById('cm-cc').value || '')
    .split(',').map(s => s.trim()).filter(Boolean);

  const ccNote = cc_emails.length ? ` and CC ${cc_emails.length} person(s)` : '';
  if (!confirm(`Post a Jira comment on ${chosen.length} issue(s), mentioning each owner${ccNote}? This writes real comments to Jira.`)) return;

  const queue = {
    created:   new Date().toISOString(),
    template,
    cc_emails,
    items: chosen.map(i => ({
      key: i.key, owner: i.owner, assignee_id: i.assignee_id, type: i.type,
    })),
  };

  const btn = document.getElementById('cm-post-btn');
  const status = document.getElementById('cm-status');
  btn.disabled = true;
  status.textContent = 'Queuing…';

  try {
    // 1) Commit the ENCRYPTED queue (it carries owner names + issue keys).
    const ok = await _saveEncStore('comment_queue.json', queue,
                 `Queue ${chosen.length} Jira comment(s)`);
    if (!ok) throw new Error('could not write encrypted queue');

    // 2) Dispatch the comments workflow to post them.
    status.textContent = 'Triggering Jira post…';
    const disp = await fetch(`https://api.github.com/repos/${repo}/actions/workflows/comments.yml/dispatches`,{
      method:'POST',
      headers:{'Authorization':`Bearer ${GH_PAT}`,'Accept':'application/vnd.github+json','Content-Type':'application/json'},
      body: JSON.stringify({ ref:'main', inputs:{} })
    });
    if (disp.status !== 204) {
      const e = await disp.json().catch(()=>({}));
      throw new Error(e.message || ('HTTP ' + disp.status));
    }
    status.textContent = '';
    toast(`✓ Queued — ${chosen.length} comment(s) posting to Jira in ~30–60s.`);
    closeModal('comment-modal');
  } catch (e) {
    status.textContent = '';
    toast('Failed: ' + e.message);
  } finally {
    window.__COMMENT_PW = '';   // don't leave the comment password in memory
    btn.disabled = false;
    cmRecount();
  }
}

// ── Team directory (emails) ────────────────────────────────────────────────
let PEOPLE_EMAILS = {};   // accountId (or "name:Name") -> manually-entered email

function _collectPeople(){
  const out = [];
  (REPORT.rows || []).forEach(r => {
    if (!r.owner || r.owner === 'Unassigned') return;
    let id = '', email = '';
    (r.issues || []).forEach(i => {
      if (!id && i.assignee_id) id = i.assignee_id;
      if (!email && i.assignee_email) email = i.assignee_email;
    });
    out.push({ id: id || ('name:' + r.owner), name: r.owner, jira_email: email, count: (r.issues || []).length });
  });
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

async function openDirectoryModal(){
  if (!REPORT) return;
  const stored = await _loadEncStore('people_emails.json');
  PEOPLE_EMAILS = (stored && typeof stored === 'object' && !Array.isArray(stored)) ? stored : {};
  _renderDirectory();
  openModal('directory-modal');
}

function _renderDirectory(){
  const people = _collectPeople();
  const base = (REPORT.jira_base_url || 'https://fibtask.atlassian.net').replace(/\/+$/,'');
  document.getElementById('dir-sub').textContent =
    `${people.length} people with assigned work · email where Jira allows it, otherwise their Jira account ID (saved encrypted).`;
  const rows = people.map((p, idx) => {
    const override = PEOPLE_EMAILS[p.id] || '';
    const val = override || p.jira_email || '';
    const src = (p.jira_email && val === p.jira_email)
      ? '<span style="font-size:10px;color:#0f766e;font-weight:700;background:#ccfbf1;padding:1px 6px;border-radius:999px">from Jira</span>' : '';
    const hasId = !p.id.startsWith('name:');
    // Jira account ID — shown as a fallback identifier; click to copy, or open
    // the person's Jira profile.
    const idCell = hasId
      ? `<span title="Click to copy Jira account ID" onclick="_copyText('${esc(p.id)}')" style="cursor:pointer;font-family:'JetBrains Mono',Consolas,monospace;font-size:10.5px;color:#0369a1">${esc(p.id)}</span>
         <a href="${base}/jira/people/${encodeURIComponent(p.id)}" target="_blank" rel="noopener" title="Open Jira profile" style="margin-left:5px;color:#64748b;text-decoration:none">↗</a>`
      : `<span style="font-size:10.5px;color:#cbd5e1">no Jira ID</span>`;
    return `<tr style="border-bottom:1px solid #f1f5f9">
      <td style="padding:7px 8px;color:#94a3b8;font-size:12px;text-align:right;width:28px">${idx + 1}</td>
      <td style="padding:7px 8px;font-size:13px;color:#0f172a;white-space:nowrap">${esc(p.name)}
        <div style="margin-top:2px">${idCell}</div>
        <div style="font-size:10px;color:#94a3b8">${p.count} task(s)</div></td>
      <td style="padding:7px 8px">
        <input type="email" data-pid="${esc(p.id)}" value="${esc(val)}" placeholder="name@company.com"
               style="width:100%;box-sizing:border-box;font-size:12.5px;padding:6px 9px;border:1px solid #cbd5e1;border-radius:7px">
      </td>
      <td style="padding:7px 8px;width:64px">${src}</td>
    </tr>`;
  }).join('');
  document.getElementById('dir-body').innerHTML = people.length
    ? `<table style="width:100%;border-collapse:collapse"><tbody>${rows}</tbody></table>`
    : '<div style="padding:24px;text-align:center;color:#94a3b8">No assigned people.</div>';
}

function _dirCollectInputs(){
  const map = {};
  document.querySelectorAll('#dir-body input[data-pid]').forEach(inp => {
    const v = (inp.value || '').trim();
    if (v) map[inp.getAttribute('data-pid')] = v;
  });
  return map;
}

async function saveDirectory(){
  const btn = document.getElementById('dir-save-btn');
  const status = document.getElementById('dir-status');
  PEOPLE_EMAILS = _dirCollectInputs();
  if (btn) btn.disabled = true;
  status.textContent = 'Saving…';
  try {
    const ok = await _saveEncStore('people_emails.json', PEOPLE_EMAILS, 'Update team email directory');
    status.textContent = ok ? '✓ Saved (encrypted).' : '';
    if (ok) setTimeout(() => status.textContent = '', 2500);
  } catch(e) { status.textContent = 'Save failed: ' + e.message; }
  finally { if (btn) btn.disabled = false; }
}

function _copyText(t){
  navigator.clipboard.writeText(t).then(
    () => toast('✓ Copied: ' + (t.length > 28 ? t.slice(0,28) + '…' : t)),
    () => toast('Copy failed.'));
}

function copyAllEmails(){
  const inputs = _dirCollectInputs();
  const people = _collectPeople();
  const parts = []; let nEmail = 0, nId = 0;
  people.forEach(p => {
    const email = inputs[p.id] || p.jira_email || '';
    if (email) { parts.push(email); nEmail++; }
    else if (!p.id.startsWith('name:')) { parts.push(p.id); nId++; }   // fall back to Jira ID
  });
  if (!parts.length) { toast('Nothing to copy yet.'); return; }
  navigator.clipboard.writeText(parts.join(', ')).then(
    () => toast(`✓ Copied ${nEmail} email(s)` + (nId ? ` + ${nId} Jira ID(s)` : '') + '.'),
    () => toast('Copy failed.'));
}

// ── Overdue export / copy helpers ──────────────────────────────────────────
function _overdueDaysAgo(due) {
  if (!due) return '';
  const d = new Date(String(due).length <= 10 ? due + 'T00:00:00Z' : due);
  if (isNaN(d.getTime())) return '';
  const days = Math.max(0, Math.floor((Date.now() - d.getTime()) / 86400000));
  if (days === 0) return 'today';
  if (days === 1) return '1 day';
  if (days < 30)  return `${days} days`;
  const months = Math.round(days/30);
  if (months < 12) return `${months} mo`;
  return `${Math.round(days/365)} yr`;
}

// Build an Outlook-friendly self-contained HTML table (inline styles, no
// external CSS, clickable Jira links).
function _buildOverdueRichHTML() {
  const hide = (hiddenPeople && hiddenPeople.size) ? hiddenPeople : null;
  const items = _collectOverdue(hide);
  const base = (REPORT.jira_base_url || 'https://fibtask.atlassian.net').replace(/\/+$/,'');
  const reportDate = esc(REPORT.date || '');
  const projectName = (REPORT.jira_base_url||'').includes('fibtask') ? 'FIBTMP' : 'PMO';

  // Group by owner; sort owners by earliest (worst) due date.
  const groups = {};
  items.forEach(i => { (groups[i.owner] = groups[i.owner] || []).push(i); });
  const owners = Object.keys(groups).sort((a,b) => {
    const aDue = groups[a][0]?.due || '';
    const bDue = groups[b][0]?.due || '';
    return aDue < bDue ? -1 : 1;
  });

  // Distinct accent stripe per owner block.
  const accents = ['#dc2626','#ea580c','#d97706','#0891b2','#7c3aed','#db2777','#0f766e','#4f46e5'];

  let n = 0;
  const blocks = owners.map((owner, oi) => {
    const list = groups[owner];
    const accent = accents[oi % accents.length];
    const rows = list.map(i => {
      n++;
      const url   = `${base}/browse/${encodeURIComponent(i.key)}`;
      const days  = _overdueDaysAgo(i.due);
      const dueStr= i.due ? esc(String(i.due).slice(0,10)) : '—';
      const bg = n % 2 ? '#fef7f7' : '#ffffff';
      return `<tr style="background:${bg}">
        <td style="padding:9px 10px;border-bottom:1px solid #fecaca;font-family:Consolas,'Courier New',monospace;font-size:12px;font-weight:800;color:#7f1d1d;text-align:center;width:38px">${n}</td>
        <td style="padding:9px 12px;border-bottom:1px solid #fecaca;font-family:Consolas,'Courier New',monospace;font-size:12px;font-weight:700;color:#1e40af;white-space:nowrap">
          <a href="${url}" style="color:#1e40af;text-decoration:none">${esc(i.key)}</a>
        </td>
        <td style="padding:9px 12px;border-bottom:1px solid #fecaca;font-size:13px;color:#0f172a">${esc(i.summary || '(no summary)')}</td>
        <td style="padding:9px 12px;border-bottom:1px solid #fecaca;font-size:11.5px;font-weight:700;color:#475569;white-space:nowrap">${esc(i.status)}</td>
        <td style="padding:9px 12px;border-bottom:1px solid #fecaca;font-family:Consolas,'Courier New',monospace;font-size:12px;color:#7f1d1d;white-space:nowrap">${dueStr}</td>
        <td style="padding:9px 12px;border-bottom:1px solid #fecaca;font-size:12px;font-weight:800;color:#991b1b;white-space:nowrap">${esc(days)} ago</td>
      </tr>`;
    }).join('');

    return `<div style="margin-bottom:14px;border:1px solid #fecaca;border-left:6px solid ${accent};border-radius:8px;overflow:hidden;background:#ffffff;box-shadow:0 1px 3px rgba(0,0,0,.04)">
      <div style="padding:10px 14px;border-bottom:1px solid #fecaca;background:linear-gradient(90deg,${accent}1a,#ffffff)">
        <table cellpadding="0" cellspacing="0" border="0" width="100%"><tr>
          <td style="vertical-align:middle">
            <span style="display:inline-block;background:${accent};color:#fff;padding:4px 12px;border-radius:999px;font-size:12px;font-weight:800;letter-spacing:.02em">${esc(owner)}</span>
          </td>
          <td style="vertical-align:middle;text-align:right;font-size:12.5px;font-weight:700;color:${accent}">${list.length} overdue task${list.length===1?'':'s'}</td>
        </tr></table>
      </div>
      <table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;width:100%">
        <thead>
          <tr style="background:#fef2f2">
            <th style="text-align:center;padding:8px 10px;font-size:10px;font-weight:800;letter-spacing:.08em;color:#7f1d1d;text-transform:uppercase;border-bottom:2px solid #fca5a5;width:38px">#</th>
            <th style="text-align:left;padding:8px 12px;font-size:10px;font-weight:800;letter-spacing:.08em;color:#7f1d1d;text-transform:uppercase;border-bottom:2px solid #fca5a5">Key</th>
            <th style="text-align:left;padding:8px 12px;font-size:10px;font-weight:800;letter-spacing:.08em;color:#7f1d1d;text-transform:uppercase;border-bottom:2px solid #fca5a5">Summary</th>
            <th style="text-align:left;padding:8px 12px;font-size:10px;font-weight:800;letter-spacing:.08em;color:#7f1d1d;text-transform:uppercase;border-bottom:2px solid #fca5a5">Status</th>
            <th style="text-align:left;padding:8px 12px;font-size:10px;font-weight:800;letter-spacing:.08em;color:#7f1d1d;text-transform:uppercase;border-bottom:2px solid #fca5a5">Due</th>
            <th style="text-align:left;padding:8px 12px;font-size:10px;font-weight:800;letter-spacing:.08em;color:#7f1d1d;text-transform:uppercase;border-bottom:2px solid #fca5a5">Past due</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  }).join('');

  return `<div style="font-family:-apple-system,Segoe UI,Arial,sans-serif;max-width:920px">
    <div style="background:linear-gradient(135deg,#dc2626,#991b1b);color:#fff;padding:16px 20px;border-radius:10px;margin-bottom:14px;box-shadow:0 4px 12px rgba(220,38,38,.25)">
      <div style="font-size:20px;font-weight:800;letter-spacing:-.01em">⚠ Overdue tasks — ${projectName}</div>
      <div style="font-size:12.5px;opacity:.95;margin-top:3px">${reportDate} · <strong>${items.length}</strong> task(s) past due across <strong>${owners.length}</strong> owner(s) · grouped per person, worst first</div>
    </div>
    ${blocks || '<div style="padding:24px;text-align:center;color:#64748b">No overdue tasks.</div>'}
    <div style="font-size:11px;color:#94a3b8;margin-top:8px">Click any task key to open in Jira. Snapshot ${reportDate}.</div>
  </div>`;
}

async function copyOverdueRichHTML() {
  const html = _buildOverdueRichHTML();
  try {
    if (navigator.clipboard && window.ClipboardItem) {
      const blob = new Blob([html], {type: 'text/html'});
      const textBlob = new Blob([html.replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim()], {type: 'text/plain'});
      await navigator.clipboard.write([new ClipboardItem({'text/html': blob, 'text/plain': textBlob})]);
      toast('✓ Copied — paste into Outlook (Ctrl+V) for formatted table with clickable links.');
    } else {
      // Fallback: legacy execCommand using a hidden contenteditable div
      const div = document.createElement('div');
      div.contentEditable = 'true';
      div.style.cssText = 'position:fixed;left:-9999px;top:0';
      div.innerHTML = html;
      document.body.appendChild(div);
      const range = document.createRange();
      range.selectNodeContents(div);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      document.execCommand('copy');
      sel.removeAllRanges();
      div.remove();
      toast('✓ Copied — paste into Outlook for formatted output.');
    }
  } catch (e) {
    console.error('[copy-overdue-html]', e);
    toast('Copy failed: '+e.message);
  }
}

async function _captureOverdueCanvas() {
  await _ensureHtml2Canvas();
  // Render the rich HTML into an off-screen container so the captured
  // image always shows the styled, branded version (not the modal layout).
  const host = document.createElement('div');
  // Fixed desktop width so the capture never depends on the (possibly tiny)
  // mobile viewport — avoids 0-width collapse / createPattern crashes.
  host.style.cssText = 'position:fixed;left:-9999px;top:0;width:1180px;background:#ffffff;padding:20px';
  host.innerHTML = _buildOverdueRichHTML();
  document.body.appendChild(host);
  try {
    return await _h2c(host);
  } finally {
    host.remove();
  }
}

async function copyOverdueImage() {
  try {
    const cv = await _captureOverdueCanvas();
    await _copyCanvasToClipboard(cv, `overdue-${(REPORT.date||'report')}.png`);
  } catch (e) {
    console.error('[copy-overdue-img]', e);
    toast('Copy image failed: '+e.message);
  }
}

async function exportOverduePNG(mobile) {
  try {
    const cv = await _captureOverdueCanvas();
    const fn = `overdue-${(REPORT.date||'report')}.jpg`;
    mobile ? await _shareCanvasMobile(cv, fn) : await _shareOrDownloadCanvas(cv, fn, `✓ Saved ${fn}`);
  } catch (e) {
    console.error('[export-overdue]', e);
    toast('Export failed: '+e.message);
  }
}

// ── Overdue tasks → colour-coded Excel (grouped by owner, worst first) ─────
// Raw integer days-overdue (unlike _overdueDaysAgo's human string) so the
// Excel column can be coloured on a scale and still sorted/filtered as a number.
function _overdueDaysNum(due) {
  if (!due) return null;
  const d = new Date(String(due).length <= 10 ? due + 'T00:00:00Z' : due);
  if (isNaN(d.getTime())) return null;
  return Math.max(0, Math.floor((Date.now() - d.getTime()) / 86400000));
}
function _overdueDaysFill(days) {
  if (days === null)  return 'E7E6E6'; // unknown due date — grey
  if (days >= 30)      return 'F4B7B7'; // long overdue — deep red
  if (days >= 7)       return 'FFCFCF'; // overdue a while — red
  return 'FFE699';                      // just tipped over — amber
}

async function exportOverdueExcel() {
  if (!REPORT) return;
  const hide = (hiddenPeople && hiddenPeople.size) ? hiddenPeople : null;
  const items = _collectOverdue(hide);
  if (!items.length) { toast('No overdue tasks to export. 🎉'); return; }

  toast('Generating Excel…');
  const base = (REPORT.jira_base_url || 'https://fibtask.atlassian.net').replace(/\/+$/,'');
  const projectName = (REPORT.jira_base_url||'').includes('fibtask') ? 'FIBTMP' : 'PMO';
  const reportDate = REPORT.date || '';

  // Same grouping/order as the on-screen modal and the Outlook copy: bucket
  // by owner, worst (earliest) due date first, so the Excel reads the same
  // as everything else in this feature.
  const groups = {};
  items.forEach(i => { (groups[i.owner] = groups[i.owner] || []).push(i); });
  const owners = Object.keys(groups).sort((a,b) => {
    const aDue = groups[a][0]?.due || '';
    const bDue = groups[b][0]?.due || '';
    return aDue < bDue ? -1 : 1;
  });
  const accents = ['DC2626','EA580C','D97706','0891B2','7C3AED','DB2777','0F766E','4F46E5'];
  const ownerAccent = {};
  owners.forEach((o,i) => ownerAccent[o] = accents[i % accents.length]);

  const loadXlsxStyle = () => new Promise((resolve, reject) => {
    if (window.XLSX && XLSX.utils && XLSX.writeFile) return resolve();
    const s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/npm/xlsx-js-style/dist/xlsx.bundle.js';
    s.onload = resolve;
    s.onerror = () => reject(new Error('Failed to load styled XLSX library.'));
    document.head.appendChild(s);
  });

  try {
    await loadXlsxStyle();

    const header = ['#','Key','Summary','Owner','Status','Due Date','Days Overdue','Link'];
    let n = 0;
    const rows = [];
    owners.forEach(owner => {
      groups[owner].forEach(i => {
        n++;
        rows.push({
          n, key: i.key, summary: i.summary || '(no summary)', owner,
          status: i.status || '', due: i.due ? String(i.due).slice(0,10) : '—',
          days: _overdueDaysNum(i.due), link: `${base}/browse/${encodeURIComponent(i.key)}`
        });
      });
    });

    const now = new Date();
    const generatedAt = now.toLocaleString('en-GB', {day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'});
    const titleText = `⚠ Overdue Tasks — ${projectName}  ·  ${reportDate}  ·  ${items.length} task(s) across ${owners.length} owner(s)  ·  Generated ${generatedAt}`;
    const HEADER_ROW = 1, DATA_START = 2;
    const lastCol = header.length - 1;
    const lastColLetter = XLSX.utils.encode_col(lastCol);

    const aoa = [
      [titleText],
      header,
      ...rows.map(r => [r.n, r.key, r.summary, r.owner, r.status, r.due, r.days===null?'—':r.days, r.link])
    ];
    const ws = XLSX.utils.aoa_to_sheet(aoa);
    ws['!cols'] = [{wch:5},{wch:14},{wch:60},{wch:20},{wch:20},{wch:12},{wch:13},{wch:40}];
    ws['!rows'] = [{hpx:22},{hpx:30}, ...rows.map(()=>({hpx:24}))];
    ws['!merges'] = [{ s:{r:0,c:0}, e:{r:0,c:lastCol} }];
    ws['!freeze'] = {xSplit:0, ySplit:DATA_START};
    ws['!autofilter'] = {ref:`A${HEADER_ROW+1}:${lastColLetter}${rows.length+DATA_START}`};

    const titleAddr = XLSX.utils.encode_cell({r:0,c:0});
    if (ws[titleAddr]) ws[titleAddr].s = { font:{bold:true,color:{rgb:'FFFFFF'},sz:12}, fill:{fgColor:{rgb:'991B1B'}}, alignment:{horizontal:'left',vertical:'center'} };

    const headStyle = { font:{bold:true,color:{rgb:'FFFFFF'},sz:11}, fill:{fgColor:{rgb:'DC2626'}}, alignment:{horizontal:'center',vertical:'center',wrapText:true}, border:{bottom:{style:'thin',color:{rgb:'7F1D1D'}}} };
    for (let c=0;c<header.length;c++){
      const addr = XLSX.utils.encode_cell({r:HEADER_ROW,c});
      if (ws[addr]) ws[addr].s = headStyle;
    }

    rows.forEach((r,i) => {
      const rr = i + DATA_START;
      const bandFill = i % 2 === 0 ? 'FFFFFF' : 'FEF2F2';
      const border = {bottom:{style:'thin',color:{rgb:'FCA5A5'}}};

      let addr = XLSX.utils.encode_cell({r:rr,c:0});
      if (ws[addr]) ws[addr].s = { font:{bold:true,color:{rgb:'7F1D1D'},sz:10}, fill:{fgColor:{rgb:bandFill}}, alignment:{horizontal:'center',vertical:'center'}, border };

      addr = XLSX.utils.encode_cell({r:rr,c:1}); // Key — clickable
      if (ws[addr]) {
        ws[addr].s = { font:{bold:true,color:{rgb:'1155CC'},underline:true,sz:10}, fill:{fgColor:{rgb:bandFill}}, alignment:{vertical:'center'}, border };
        ws[addr].l = { Target: r.link, Tooltip: 'Open in Jira' };
      }

      addr = XLSX.utils.encode_cell({r:rr,c:2}); // Summary
      if (ws[addr]) ws[addr].s = { font:{sz:10}, fill:{fgColor:{rgb:bandFill}}, alignment:{vertical:'center', wrapText:true}, border };

      addr = XLSX.utils.encode_cell({r:rr,c:3}); // Owner badge
      if (ws[addr]) ws[addr].s = { font:{bold:true,color:{rgb:'FFFFFF'},sz:10}, fill:{fgColor:{rgb:ownerAccent[r.owner]}}, alignment:{horizontal:'center',vertical:'center'}, border };

      addr = XLSX.utils.encode_cell({r:rr,c:4}); // Status
      if (ws[addr]) ws[addr].s = { font:{sz:10}, fill:{fgColor:{rgb:_epicStatusFill(r.status)}}, alignment:{horizontal:'center',vertical:'center',wrapText:true}, border };

      addr = XLSX.utils.encode_cell({r:rr,c:5}); // Due date
      if (ws[addr]) ws[addr].s = { font:{sz:10,color:{rgb:'7F1D1D'}}, fill:{fgColor:{rgb:bandFill}}, alignment:{horizontal:'center',vertical:'center'}, border };

      addr = XLSX.utils.encode_cell({r:rr,c:6}); // Days overdue
      if (ws[addr]) ws[addr].s = { font:{bold:true,color:{rgb:(r.days!==null && r.days>=30)?'C00000':'7F1D1D'},sz:10}, fill:{fgColor:{rgb:_overdueDaysFill(r.days)}}, alignment:{horizontal:'center',vertical:'center'}, border };

      addr = XLSX.utils.encode_cell({r:rr,c:7}); // Link
      if (ws[addr]) {
        ws[addr].s = { font:{color:{rgb:'1155CC'},underline:true,sz:9}, fill:{fgColor:{rgb:bandFill}}, alignment:{vertical:'center'}, border };
        ws[addr].l = { Target: r.link, Tooltip: 'Open in Jira' };
      }
    });

    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Overdue');
    XLSX.writeFile(wb, `overdue-${reportDate || 'report'}.xlsx`);
    toast('✓ Overdue Excel downloaded.');
  } catch (e) {
    console.error('[export-overdue-excel]', e);
    toast('Export failed: '+e.message);
  }
}

// Render the open person modal's task list to a canvas. Builds an offscreen
// HTML version (same styling as the clipboard payload) and rasterises it via
// html2canvas so the result is a clean image — no modal chrome, no scroll bars.
async function _capturePersonModalCanvas() {
  const btn = document.getElementById('pm-copy-btn');
  const html = btn?.dataset?.html || '';
  if (!html) { toast('No data to capture.'); return null; }
  // Render the rich HTML payload into an offscreen div for crisp output.
  const host = document.createElement('div');
  host.style.cssText = 'position:fixed;left:-99999px;top:0;background:#ffffff;padding:24px;width:1100px';
  host.innerHTML = html;
  document.body.appendChild(host);
  try {
    return await _h2c(host);
  } finally {
    host.remove();
  }
}

async function copyPersonTasks(btn) {
  // Copy the rich HTML table (clickable Jira links) so pasting into Outlook /
  // Teams yields a formatted table — NOT a flat image. Mirrors copyOverdueRichHTML.
  const src = document.getElementById('pm-copy-btn');
  const html = src?.dataset?.html || '';
  const tsv  = src?.dataset?.tsv  || html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  if (!html) { toast('No data to copy.'); return; }
  const orig = btn.textContent;
  btn.textContent = '… copying';
  try {
    if (navigator.clipboard && window.ClipboardItem) {
      const htmlBlob = new Blob([html], {type: 'text/html'});
      const textBlob = new Blob([tsv],  {type: 'text/plain'});
      await navigator.clipboard.write([new ClipboardItem({'text/html': htmlBlob, 'text/plain': textBlob})]);
    } else {
      // Legacy fallback: select a hidden contenteditable div and execCommand('copy')
      const div = document.createElement('div');
      div.contentEditable = 'true';
      div.style.cssText = 'position:fixed;left:-9999px;top:0';
      div.innerHTML = html;
      document.body.appendChild(div);
      const range = document.createRange();
      range.selectNodeContents(div);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      document.execCommand('copy');
      sel.removeAllRanges();
      div.remove();
    }
    btn.textContent = '✓ Copied';
    toast('✓ Copied — paste into Outlook (Ctrl+V) for a formatted table with clickable links.');
  } catch (e) {
    console.error('[copy-person]', e);
    toast('Copy failed: ' + e.message);
    btn.textContent = orig;
    return;
  }
  setTimeout(() => { btn.textContent = '📋 Copy'; }, 1400);
}

async function exportPersonTasks(mobile) {
  const btn = document.getElementById(mobile ? 'pm-export-mobile-btn' : 'pm-export-btn');
  const orig = btn ? btn.textContent : '';
  if (btn) btn.textContent = '…';
  try {
    const cv = await _capturePersonModalCanvas();
    if (!cv) { if (btn) btn.textContent = orig; return; }
    const owner = document.getElementById('pm-copy-btn')?.dataset?.owner || 'person';
    const fn = `${owner}-tasks.png`;
    mobile ? await _shareCanvasMobile(cv, fn) : await _shareOrDownloadCanvas(cv, fn, '✓ Image saved.');
  } catch (e) {
    console.error('[export-person]', e);
    toast('Export failed: ' + e.message);
  } finally {
    if (btn) setTimeout(() => { btn.textContent = orig; }, 1400);
  }
}

// ── Person Jira-links modal ────────────────────────────────────────────────
function openPersonModal(name) {
  if (!REPORT || !Array.isArray(REPORT.rows)) return;
  const row = REPORT.rows.find(r => r.owner === name);
  if (!row) return;
  const base = (REPORT.jira_base_url || 'https://fibtask.atlassian.net').replace(/\/+$/,'');
  const issues = Array.isArray(row.issues) ? row.issues : [];

  // Grouping order: Overdue first (highlighted), then categories.
  const overdue = issues.filter(i => i.overdue);
  const byCat = {'In Progress':[], 'Open':[], 'Waiting For Approval':[], 'Completed':[]};
  issues.forEach(i => {
    if (i.overdue) return; // shown under Overdue group
    (byCat[i.category] || (byCat[i.category]=[])).push(i);
  });

  const statusClass = s => {
    const n = (s||'').toLowerCase();
    if (/(done|closed|resolv|complete|available)/.test(n)) return 'st-done';
    if (/progress/.test(n))                                 return 'st-progress';
    if (/(wait|approv|review)/.test(n))                     return 'st-wait';
    if (/(hold|block|pause)/.test(n))                       return 'st-hold';
    return 'st-open';
  };
  const fmtChanged = iso => {
    if (!iso) return '';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return esc(String(iso).slice(0,10));
    const mins = Math.max(0, Math.round((Date.now() - d.getTime())/60000));
    if (mins < 1)    return 'just now';
    if (mins < 60)   return `${mins} min${mins===1?'':'s'} ago`;
    const hrs = Math.round(mins/60);
    if (hrs < 24)    return `${hrs} hour${hrs===1?'':'s'} ago`;
    const days = Math.round(hrs/24);
    if (days < 30)   return `${days} day${days===1?'':'s'} ago`;
    const months = Math.round(days/30);
    if (months < 12) return `${months} month${months===1?'':'s'} ago`;
    const years = Math.round(days/365);
    return `${years} year${years===1?'':'s'} ago`;
  };
  const renderRow = i => {
    const url = `${base}/browse/${encodeURIComponent(i.key)}`;
    const dueCls = i.overdue ? 'pm-due over' : 'pm-due';
    const due = i.due ? `<span class="${dueCls}" title="Due">${esc(i.due)}</span>` : '';
    const changed = i.changed
      ? `<span class="pm-changed" title="Last status change">${esc(fmtChanged(i.changed))}</span>` : '';
    return `<a class="pm-row" href="${url}" target="_blank" rel="noopener">
      <span class="pm-key">${esc(i.key)}</span>
      <span class="pm-summary">${esc(i.summary || '(no summary)')}</span>
      <span class="pm-status ${statusClass(i.status)}">${esc(i.status)}</span>
      ${changed}
      ${due}
    </a>`;
  };

  const renderGroup = (label, list, isOverdue) => {
    if (!list.length) return '';
    return `<div class="pm-group${isOverdue?' overdue':''}">
      <div class="pm-group-hdr">${isOverdue?'⚠ ':''}${esc(label)}
        <span class="pm-count">${list.length}</span>
      </div>
      <div class="pm-list">${list.map(renderRow).join('')}</div>
    </div>`;
  };

  let body = '';
  body += renderGroup('Overdue', overdue, true);
  ['In Progress','Open','Waiting For Approval','Completed'].forEach(cat => {
    body += renderGroup(cat, byCat[cat] || [], false);
  });
  if (!body) body = '<div class="empty">No issues assigned.</div>';

  document.getElementById('pm-name').textContent = name;
  document.getElementById('pm-sub').textContent =
    `${issues.length} issue(s) · ${overdue.length} overdue · click any row to open in Jira`;
  document.getElementById('pm-body').innerHTML = body;
  // Build Outlook-friendly clipboard payload: styled HTML table + TSV fallback.
  // Returns [bg, fg] for status pill — soft pastel backgrounds, dark text.
  const statusBg = s => {
    const n = (s||'').toLowerCase();
    if (/(done|closed|resolv|complete|available)/.test(n)) return ['#dcfce7','#166534'];   // green
    if (/progress/.test(n))                                 return ['#dbeafe','#1e40af'];   // blue
    if (/(wait|approv|review)/.test(n))                     return ['#fef3c7','#92400e'];   // amber
    if (/(hold|block|pause)/.test(n))                       return ['#fee2e2','#991b1b'];   // red
    if (/(open|to.?do|backlog|new)/.test(n))                return ['#f1f5f9','#334155'];   // slate
    return ['#ede9fe','#5b21b6'];                                                            // purple fallback
  };
  // Outlook-safe pill: use a nested 0-cellpadding table because <span
  // style="background"> is dropped by Word's rendering engine.
  const pill = (text, bg, fg) =>
    `<table cellspacing="0" cellpadding="0" border="0" style="display:inline-table;border-collapse:separate"><tr>`
    + `<td bgcolor="${bg}" style="background:${bg};color:${fg};padding:3px 10px;border-radius:11px;`
    + `font-size:11px;font-weight:700;letter-spacing:.02em;white-space:nowrap;`
    + `font-family:-apple-system,Segoe UI,Arial,sans-serif">${esc(text)}</td>`
    + `</tr></table>`;
  const tsv = ['Key\tSummary\tStatus\tDue\tOverdue\tURL'];
  const today = new Date().toISOString().slice(0,10);
  const sorted = issues.slice().sort((a,b) => {
    if (!!b.overdue - !!a.overdue) return !!b.overdue - !!a.overdue;
    const order = {'In Progress':0,'Waiting For Approval':1,'Open':2,'Completed':3};
    return (order[a.category] ?? 9) - (order[b.category] ?? 9);
  });
  const rowsHtml = sorted.map((i, idx) => {
    const url = `${base}/browse/${encodeURIComponent(i.key)}`;
    const [sBg, sFg] = statusBg(i.status);
    const zebra = idx % 2 === 0 ? '#ffffff' : '#f8fafc';
    // Overdue rows get a soft red wash + a left accent bar via the Key cell.
    const rowBg = i.overdue ? '#fef2f2' : zebra;
    const keyBorderLeft = i.overdue ? 'border-left:4px solid #dc2626;' : '';
    const dueCellColor = i.overdue ? '#991b1b' : '#475569';
    const dueCellBg    = i.overdue ? '#fee2e2' : 'transparent';
    const dueCellWeight = i.overdue ? '700' : '500';
    const dueText = i.due ? esc(i.due) + (i.overdue ? ' ⚠' : '') : '—';
    tsv.push([
      i.key || '',
      (i.summary || '').replace(/\s+/g,' ').trim(),
      i.status || '',
      i.due || '',
      i.overdue ? 'YES' : '',
      url,
    ].join('\t'));
    const tdBase = `padding:8px 12px;border:1px solid #e2e8f0;font-size:13px;background:${rowBg};vertical-align:middle`;
    return `<tr>
      <td style="${tdBase};${keyBorderLeft}font-family:Consolas,Menlo,monospace;font-size:12px;font-weight:700;white-space:nowrap"><a href="${url}" style="color:#1d4ed8;text-decoration:none">${esc(i.key)}</a></td>
      <td style="${tdBase};width:62%;color:#0f172a"><a href="${url}" style="color:#0f172a;text-decoration:none">${esc(i.summary || '(no summary)')}</a></td>
      <td style="${tdBase}">${pill(i.status||'', sBg, sFg)}</td>
      <td style="${tdBase};color:${dueCellColor};font-weight:${dueCellWeight};background:${i.overdue?dueCellBg:rowBg};font-family:Consolas,Menlo,monospace;font-size:12px;white-space:nowrap">${dueText}</td>
    </tr>`;
  }).join('');
  // Header summary chips (Outlook-safe — nested tables, not spans)
  const chip = (label, value, bg, fg) => {
    const border = bg === '#ffffff' ? '1px solid #cbd5e1' : '1px solid ' + bg;
    return `<table cellspacing="0" cellpadding="0" border="0" style="display:inline-table;border-collapse:separate;margin-right:6px"><tr>`
      + `<td bgcolor="${bg}" style="background:${bg};color:${fg};padding:5px 11px;border-radius:6px;border:${border};font-weight:700;font-size:11.5px;`
      + `font-family:-apple-system,Segoe UI,Arial,sans-serif"><font color="${fg}">${label}: ${value}</font></td></tr></table>`;
  };
  const headerChips =
    chip('Total', issues.length, '#ffffff', '#475569') +
    chip('Overdue', overdue.length, overdue.length ? '#fee2e2' : '#dcfce7', overdue.length ? '#991b1b' : '#166534') +
    chip('In Progress', issues.filter(i=>i.category==='In Progress').length, '#dbeafe', '#1e40af') +
    chip('Done', issues.filter(i=>i.category==='Completed').length, '#dcfce7', '#166534');
  const html = `<div style="font-family:-apple-system,Segoe UI,Arial,sans-serif">
    <div style="font-size:18px;font-weight:800;color:#0f172a;margin-bottom:6px;letter-spacing:-.01em">${esc(name)} — Assigned Tasks</div>
    <div style="margin-bottom:10px">${headerChips}<span style="font-size:11px;color:#94a3b8">as of ${today}</span></div>
    <table cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse;border:1px solid #cbd5e1;font-family:-apple-system,Segoe UI,Arial,sans-serif">
      <tr>
        <td bgcolor="#ffffff" style="background:#ffffff;color:#475569;padding:10px 12px;border:1px solid #cbd5e1;border-bottom:2px solid #1d4ed8;font-size:11px;font-weight:700;text-align:left;letter-spacing:.08em;text-transform:uppercase"><font color="#475569">KEY</font></td>
        <td bgcolor="#ffffff" style="width:62%;background:#ffffff;color:#475569;padding:10px 12px;border:1px solid #cbd5e1;border-bottom:2px solid #1d4ed8;font-size:11px;font-weight:700;text-align:left;letter-spacing:.08em;text-transform:uppercase"><font color="#475569">SUMMARY</font></td>
        <td bgcolor="#ffffff" style="background:#ffffff;color:#475569;padding:10px 12px;border:1px solid #cbd5e1;border-bottom:2px solid #1d4ed8;font-size:11px;font-weight:700;text-align:left;letter-spacing:.08em;text-transform:uppercase"><font color="#475569">STATUS</font></td>
        <td bgcolor="#ffffff" style="background:#ffffff;color:#475569;padding:10px 12px;border:1px solid #cbd5e1;border-bottom:2px solid #1d4ed8;font-size:11px;font-weight:700;text-align:left;letter-spacing:.08em;text-transform:uppercase"><font color="#475569">DUE</font></td>
      </tr>
      ${rowsHtml}
    </table>
  </div>`;
  const btn = document.getElementById('pm-copy-btn');
  if (btn) {
    btn.dataset.tsv = tsv.join('\n');
    btn.dataset.html = html;
    btn.dataset.owner = name;
    btn.textContent = '📋 Copy';
  }
  openModal('person-modal');
}

// ── shared snapshot table (This Week + Last Week, same structure) ──────────
function _renderSnapshotTable(rows, hidden, mode) {
  // mode = 'this' or 'last'
  if (!rows.length) return '<div class="empty">No data.</div>';
  const pick = mode==='this'
    ? r => ({total:r.total,open:r.open,ip:r.in_progress,wfa:r.waiting_for_approval,
             ov:r.overdue,done:r.completed,pct:r.this_week})
    : r => ({total:r.last_total||0,open:r.last_open||0,ip:r.last_in_progress||0,
             wfa:r.last_wfa||0,ov:r.last_overdue||0,done:r.last_completed||0,
             pct:r.last_week});

  if (mode==='last' && !rows.some(r=>r.last_week!==null))
    return '<div class="empty">No previous snapshot yet — first Sunday save will populate this.</div>';

  let h = `<table class="snap-table"><thead><tr>
    <th>Owner</th>
    <th class="c">Total</th>
    <th class="c">Open</th>
    <th class="c"><span class="lbl-full">In Progress</span><span class="lbl-abbr">WIP</span></th>
    <th class="c"><span class="lbl-full">Waiting For Approval</span><span class="lbl-abbr">WFA</span></th>
    <th class="c"><span class="lbl-full">Overdue</span><span class="lbl-abbr">O/D</span></th>
    <th class="c"><span class="lbl-full">Completed</span><span class="lbl-abbr">Done</span></th>
    <th class="c"><span class="lbl-full">Completion %</span><span class="lbl-abbr">Done %</span></th>
    <th>Owner's Progress</th>
  </tr></thead><tbody>`;

  let tT=0,tO=0,tI=0,tW=0,tOv=0,tC=0;
  rows.forEach(r => {
    if (hidden && hidden.has(r.owner)) return;
    if (mode==='last' && r.last_week===null && !r.last_total) return;
    const v = pick(r);
    const pct = v.pct===null||v.pct===undefined ? 0 : v.pct;
    const bw = Math.max(0,Math.min(100,pct));
    tT+=v.total;tO+=v.open;tI+=v.ip;tW+=v.wfa;tOv+=v.ov;tC+=v.done;

    const barCls = mode==='this' ? 'bar-green' : 'bar-brown';
    h += `<tr class="data-row" data-owner="${esc(r.owner)}">
      <td><button class="owner-cell" onclick="filterToName('${esc(r.owner)}')">${esc(r.owner)}</button></td>
      ${numTD(v.total,true)}${numTD(v.open)}${numTD(v.ip)}${numTD(v.wfa)}
      ${ovTD(v.ov)}${numTD(v.done,true)}
      <td class="c bold" style="color:${(v.pct===null||v.pct===undefined)?'#94a3b8':(v.pct>=100?'#0f172a':'#dc2626')}">${v.pct===null||v.pct===undefined?'—':v.pct+'%'}</td>
      <td style="min-width:160px">
        <div class="bar-track" style="height:14px;background:#f1f5f9;border:1px solid #e2e8f0">
          <div class="bar-fill ${barCls}" style="width:${bw}%;height:100%"></div>
        </div>
      </td>
    </tr>`;
  });

  const tP = tT ? Math.round(100*tC/tT*10)/10 : 0;
  const totBar = mode==='this' ? 'bar-green' : 'bar-brown';
  h += `<tr class="total-row">
    <td>TOTAL</td>
    <td class="c">${tT}</td><td class="c">${tO}</td>
    <td class="c">${tI}</td><td class="c">${tW}</td>
    <td class="c">${tOv>0?'<span class="ov-badge">'+tOv+'</span>':0}</td>  <!-- TOTAL overdue (no emoji) -->
    <td class="c">${tC}</td>
    <td class="c">${tP}%</td>
    <td><div class="bar-track" style="height:14px;background:#fff;border:1.5px solid #fde047">
      <div class="bar-fill ${totBar}" style="width:${Math.min(100,tP)}%;height:100%"></div>
    </div></td>
  </tr>`;
  return h + '</tbody></table>';
}

function renderThisWeek(rows, hidden) { return _renderSnapshotTable(rows, hidden, 'this'); }
function renderLastWeek(rows, hidden) { return _renderSnapshotTable(rows, hidden, 'last'); }

// ── Changes table: 3 columns (Owner, Completion %, Bidirectional Bar) ──────
function renderChanges(rows, hidden) {
  const hasLW = rows.some(r=>r.last_week!==null);
  let h = `<table style="table-layout:fixed;width:100%">
    <colgroup>
      <col style="width:28%">
      <col style="width:18%">
      <col style="width:54%">
    </colgroup>
    <thead><tr>
    <th>Owner</th>
    <th class="c">Completion Rate</th>
    <th>Week-over-Week Change</th>
  </tr></thead><tbody>`;

  let posCount=0, negCount=0, doneCount=0, stuckCount=0, newCount=0;
  rows.forEach(r => {
    if (hidden && hidden.has(r.owner)) return;
    const d = r.delta;
    const tw = r.this_week||0;
    const isNew = d===null||d===undefined;

    // Decide bar state
    let bar='', label='', labelCls='', pctCls='';
    if (isNew) {
      bar = ''; // empty bar
      label = 'New — no baseline yet';
      labelCls = 'new'; pctCls='pct-neutral'; newCount++;
    } else if (d > 0) {
      const w = Math.min(50, d);  // % of total width (capped at half)
      bar = `<div class="dbar-fill dbar-pos" style="width:${w}%"></div>`;
      label = `+${d}%`; labelCls='pos'; pctCls='pct-green'; posCount++;
    } else if (d < 0) {
      const w = Math.min(50, Math.abs(d));
      bar = `<div class="dbar-fill dbar-neg" style="width:${w}%"></div>`;
      label = `${d}%`; labelCls='neg'; pctCls='pct-red'; negCount++;
    } else {
      // delta === 0 in completion %. Look for other meaningful changes.
      const dOv  = (r.overdue||0)   - (r.last_overdue||0);
      const dTot = (r.total||0)     - (r.last_total||0);
      const dDone= (r.completed||0) - (r.last_completed||0);
      const bits = [];
      if (dTot  !== 0) bits.push(`${dTot>0?'+':''}${dTot} task${Math.abs(dTot)!==1?'s':''}`);
      if (dDone !== 0) bits.push(`${dDone>0?'+':''}${dDone} done`);
      if (dOv   !== 0) bits.push(`${dOv>0?'+':''}${dOv} overdue`);
      if (tw >= 100) {
        bar = ''; label = 'Completed'; labelCls = 'zero'; pctCls='pct-neutral'; doneCount++;
      } else if (bits.length) {
        // pct flat but underlying counts moved — show the real change.
        bar = ''; label = bits.join(' · '); labelCls = (dOv>0?'neg':'zero'); pctCls='pct-neutral'; stuckCount++;
      } else {
        bar = ''; label = '0%'; labelCls = 'neg'; pctCls='pct-red'; stuckCount++;
      }
    }

    h += `<tr class="data-row" data-owner="${esc(r.owner)}">
      <td><button class="owner-cell" onclick="filterToName('${esc(r.owner)}')">${esc(r.owner)}</button></td>
      <td class="c bold ${pctCls}" style="font-size:14px">${tw}%</td>
      <td>
        <div class="dbar" style="width:100%">${bar}<div class="dbar-lbl ${labelCls}">${label}</div></div>
      </td>
    </tr>`;
  });

  if (!hasLW) {
    h += `<tr><td colspan="3" class="empty">No previous snapshot saved yet — running update will create a baseline; auto-comparison begins from the next run.</td></tr>`;
  }

  // Total summary row
  const teamPct = REPORT.team_total;
  const teamD = REPORT.team_delta;
  let teamBar='', teamLabel='', teamCls='';
  if (teamD===null||teamD===undefined) {
    teamLabel = 'New baseline';
    teamCls = 'new';
  } else if (teamD > 0) {
    teamBar = `<div class="dbar-fill dbar-pos" style="width:${Math.min(50,teamD)}%"></div>`;
    teamLabel = `+${teamD}%`; teamCls = 'pos';
  } else if (teamD < 0) {
    teamBar = `<div class="dbar-fill dbar-neg" style="width:${Math.min(50,Math.abs(teamD))}%"></div>`;
    teamLabel = `${teamD}%`; teamCls = 'neg';
  } else {
    teamLabel = teamPct>=100 ? 'Team complete' : 'Team stalled';
    teamCls = teamPct>=100 ? 'zero' : 'neg';
    if (teamPct < 100) teamBar = `<div class="dbar-fill dbar-stuck"></div>`;
  }
  h += `<tr class="total-row">
    <td>TEAM TOTAL</td>
    <td class="c">${teamPct}%</td>
    <td><div class="dbar" style="background:#fff;border-color:#fde047;width:100%">${teamBar}<div class="dbar-lbl ${teamCls}">${teamLabel}</div></div></td>
  </tr>`;

  // Distribution summary card
  h += `</tbody></table>
    <div style="padding:14px 18px;background:#fafbfc;border-top:1px solid #e8eef5;
         display:flex;gap:14px;flex-wrap:wrap;font-size:12.5px">
      <span><strong style="color:#059669">${posCount}</strong> improving</span>
      <span><strong style="color:#dc2626">${negCount}</strong> declining</span>
      <span><strong style="color:#dc2626">${stuckCount}</strong> stuck below 100%</span>
      <span><strong style="color:#334155">${doneCount}</strong> at 100%</span>
      ${newCount?`<span><strong style="color:#92400e">${newCount}</strong> new</span>`:''}
    </div>`;
  return h;
}

// ── render HISTORY (full snapshot tables, one per saved date) ──────────────
let histRange = 0;   // 0 = show ALL snapshots by default
function setRange(n, btn) {
  histRange = n;
  document.querySelectorAll('.rbtn').forEach(b=>b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  buildHistTable();
}

function _snapshotToRows(snap) {
  // convert history snapshot into "rows" shape compatible with _renderSnapshotTable
  const rows = [];
  Object.keys(snap.people||{}).sort((a,b)=>a.toLowerCase().localeCompare(b.toLowerCase())).forEach(name => {
    const v = (snap.people||{})[name];
    if (typeof v !== 'object') {
      // legacy: pct only
      rows.push({owner:name, total:0, open:0, in_progress:0, waiting_for_approval:0,
                 overdue:0, completed:0, this_week:v, last_week:null,
                 last_total:0, last_open:0, last_in_progress:0, last_wfa:0,
                 last_overdue:0, last_completed:0, delta:null});
    } else {
      rows.push({
        owner: name,
        total: v.total||0, open: v.open||0,
        in_progress: v.in_progress||0,
        waiting_for_approval: v.waiting_for_approval||0,
        overdue: v.overdue||0, completed: v.completed||v.done||0,
        this_week: v.pct,
        last_week: null,
        last_total:0,last_open:0,last_in_progress:0,last_wfa:0,last_overdue:0,last_completed:0,
        delta: null,
      });
    }
  });
  return rows;
}

// Stash for export — make snapshot rows / snapshot objects reachable by id
const _HIST_ROWS_CACHE = {};
const _HIST_SNAP_CACHE = {};

function _renderHistChangesTable(curr, prev) {
  // mini Changes table: Owner | Completion % | change vs prev (with bidirectional bar)
  const currMap = {}; (curr.people||{}).forEach? null : null;
  Object.keys(curr.people||{}).forEach(n => { currMap[n] = curr.people[n]; });
  const prevMap = {};
  Object.keys(prev.people||{}).forEach(n => { prevMap[n] = prev.people[n]; });
  const allNames = [...new Set([...Object.keys(currMap), ...Object.keys(prevMap)])]
    .sort((a,b)=>a.toLowerCase().localeCompare(b.toLowerCase()));

  let h = `<table style="table-layout:fixed;width:100%">
    <colgroup>
      <col style="width:30%"><col style="width:18%"><col style="width:52%">
    </colgroup>
    <thead><tr><th>Owner</th><th class="c">Completion Rate</th><th>Change vs previous week</th></tr></thead>
    <tbody>`;

  const hide = (hiddenPeople && hiddenPeople.size) ? hiddenPeople : null;
  allNames.forEach(n => {
    if (hide && hide.has(n)) return;
    const c = currMap[n], p = prevMap[n];
    const cPct = c ? (typeof c==='object'?c.pct:c) : null;
    const pPct = p ? (typeof p==='object'?p.pct:p) : null;
    const isNew = pPct===null||pPct===undefined;
    const d = (cPct!==null && !isNew) ? Math.round((cPct-pPct)*10)/10 : null;

    let bar='', label='', labelCls='', pctCls='pct-neutral';
    if (cPct === null) {
      label='(no longer assigned)'; labelCls='new'; pctCls='pct-neutral';
    } else if (isNew) {
      label='New — no baseline'; labelCls='new';
    } else if (d > 0) {
      const w = Math.min(50, d);
      bar = `<div class="dbar-fill dbar-pos" style="width:${w}%"></div>`;
      label = `+${d}%`; labelCls='pos'; pctCls='pct-green';
    } else if (d < 0) {
      const w = Math.min(50, Math.abs(d));
      bar = `<div class="dbar-fill dbar-neg" style="width:${w}%"></div>`;
      label = `${d}%`; labelCls='neg'; pctCls='pct-red';
    } else {
      // pct unchanged — surface other deltas (overdue, total, completed)
      const cObj = (typeof c==='object') ? c : {};
      const pObj = (typeof p==='object') ? p : {};
      const dOv  = (cObj.overdue||0)             - (pObj.overdue||0);
      const dTot = (cObj.total||0)               - (pObj.total||0);
      const dDone= (cObj.completed||cObj.done||0) - (pObj.completed||pObj.done||0);
      const bits = [];
      if (dTot  !== 0) bits.push(`${dTot>0?'+':''}${dTot} task${Math.abs(dTot)!==1?'s':''}`);
      if (dDone !== 0) bits.push(`${dDone>0?'+':''}${dDone} done`);
      if (dOv   !== 0) bits.push(`${dOv>0?'+':''}${dOv} overdue`);
      if (cPct >= 100) { label='Completed'; labelCls='zero'; }
      else if (bits.length) { label=bits.join(' · '); labelCls=(dOv>0?'neg':'zero'); pctCls='pct-neutral'; }
      else { bar=''; label='0%'; labelCls='neg'; pctCls='pct-red'; }
    }

    h += `<tr class="data-row" data-owner="${esc(n)}">
      <td><button class="owner-cell" onclick="filterToName('${esc(n)}')">${esc(n)}</button></td>
      <td class="c bold ${pctCls}" style="font-size:14px">${cPct!==null?cPct+'%':'—'}</td>
      <td><div class="dbar" style="width:100%">${bar}<div class="dbar-lbl ${labelCls}">${label}</div></div></td>
    </tr>`;
  });

  // Team total row — recompute from non-hidden people so it stays in sync
  // with the rest of the site (snap.team_total was frozen at save time).
  const _team = (peopleObj) => {
    let tot=0, done=0;
    Object.entries(peopleObj||{}).forEach(([n,p]) => {
      if (hide && hide.has(n)) return;
      const v = (typeof p === 'object') ? p : {};
      tot  += v.total || 0;
      done += (v.done != null ? v.done : (v.completed || 0));
    });
    return tot ? Math.round(1000*done/tot)/10 : 0;
  };
  const currTeam = _team(curr.people);
  const prevTeam = _team(prev.people);
  const teamD = Math.round((currTeam - prevTeam)*10)/10;
  let teamBar='', teamLabel='', teamCls='zero';
  if (teamD > 0) { teamBar=`<div class="dbar-fill dbar-pos" style="width:${Math.min(50,teamD)}%"></div>`; teamLabel=`+${teamD}%`; teamCls='pos'; }
  else if (teamD < 0) { teamBar=`<div class="dbar-fill dbar-neg" style="width:${Math.min(50,Math.abs(teamD))}%"></div>`; teamLabel=`${teamD}%`; teamCls='neg'; }
  else teamLabel = currTeam>=100 ? 'Team complete' : 'No change';
  h += `<tr class="total-row">
    <td>TEAM TOTAL</td>
    <td class="c">${currTeam}%</td>
    <td><div class="dbar" style="background:#fff;border-color:#fde047;width:100%">${teamBar}<div class="dbar-lbl ${teamCls}">${teamLabel}</div></div></td>
  </tr>`;

  return h + '</tbody></table>';
}

function buildHistTable() {
  const hist = REPORT.history||[];
  const wrap = document.getElementById('tbl-hist');
  if (!hist.length) {
    wrap.innerHTML = '<div class="empty" style="padding:40px">No history yet — click <strong>Save Snapshot</strong> in the top bar to add one now, or wait for the weekly auto-save.</div>';
    return;
  }

  // Filter to range
  const sliced = (histRange===0 ? hist.slice() : hist.slice(-Math.max(1, Math.floor(histRange/7)+2)));
  const ordered = sliced.slice().reverse();  // newest first
  const totalWeeks = sliced.length;

  // Clear caches
  Object.keys(_HIST_ROWS_CACHE).forEach(k => delete _HIST_ROWS_CACHE[k]);
  Object.keys(_HIST_SNAP_CACHE).forEach(k => delete _HIST_SNAP_CACHE[k]);

  let html = `<div style="font-size:12.5px;color:#64748b;margin-bottom:18px;padding:0 4px">
    Showing <strong>${ordered.length}</strong> of ${hist.length} snapshots ·
    Newest first · Each weekly block has its own Snapshot + Changes tables.
  </div>`;

  // Helper — recompute team total from a snapshot's people excluding the
  // CURRENTLY hidden list (snap.team_total was frozen at save time).
  const _hide = (hiddenPeople && hiddenPeople.size) ? hiddenPeople : null;
  const _histTeam = (peopleObj) => {
    let tot=0, done=0;
    Object.entries(peopleObj||{}).forEach(([n,p]) => {
      if (_hide && _hide.has(n)) return;
      const v = (typeof p === 'object') ? p : {};
      tot  += v.total || 0;
      done += (v.done != null ? v.done : (v.completed || 0));
    });
    return tot ? Math.round(1000*done/tot)/10 : 0;
  };

  ordered.forEach((snap, idx) => {
    // Week number: count down from totalWeeks (newest = highest)
    const sliceIdx = sliced.indexOf(snap);
    const weekNum = sliceIdx + 1;          // 1-based from oldest
    const colorIdx = sliceIdx % 8;
    const rows = _snapshotToRows(snap);
    const cacheKey = `hist_${snap.date}`;
    _HIST_ROWS_CACHE[cacheKey] = rows;
    _HIST_SNAP_CACHE[cacheKey] = snap;
    const snapTeam = _histTeam(snap.people);

    // Find the previous snapshot (older) for week-over-week comparison
    const prev = ordered[idx+1] || null;
    if (prev) _HIST_SNAP_CACHE[`prev_${snap.date}`] = prev;

    // Label
    const labelTxt = (idx===0)
      ? 'Latest snapshot'
      : (idx===ordered.length-1 ? 'Earliest snapshot in range' : `Snapshot ${ordered.length-idx} of ${ordered.length}`);

    // Colorful week divider
    html += `<div class="week-divider week-color-${colorIdx}">
      <span class="week-num-badge">WEEK ${weekNum}</span>
      <span class="week-divider-label">${labelTxt}${snap.is_weekly?' · weekly baseline':''}  ·  Team ${snapTeam}%  ·  ${Object.keys(snap.people||{}).filter(n=>!_hide||!_hide.has(n)).length} members</span>
      <span class="week-date-big">${formatDateLong(snap.date)}</span>
    </div>`;

    // 1. Snapshot table (same as This Week structure)
    html += `<div class="col-block">
      <div class="col-hdr">
        <div class="col-hdr-label">
          <span class="col-dot dot-blue"></span>
          <span class="col-hdr-title">Snapshot</span>
        </div>
        <div class="col-hdr-date">${formatDateLong(snap.date)}</div>
        <div class="col-hdr-actions">
          <button class="col-hdr-btn" onclick="copyHistTable(this)" title="Copy this table as image">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            Copy
          </button>
          <button class="col-hdr-btn" onclick="exportHistTable(this,'snapshot-${snap.date}',false)" title="Download to PC">PC</button>
          <button class="col-hdr-btn" onclick="exportHistTable(this,'snapshot-${snap.date}',true)" title="Share to mobile">Mobile</button>
          <button class="col-hdr-btn" style="border-color:#fecaca;color:#b91c1c" onclick="deleteWeekSnapshot('${snap.date}')" title="Delete this snapshot from history (requires delete password)">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>
            Delete
          </button>
        </div>
      </div>
      <div style="overflow-x:auto">${_renderSnapshotTable(rows, (hiddenPeople && hiddenPeople.size) ? hiddenPeople : null, 'this')}</div>
    </div>`;

    // 2. Changes section (only when a previous snapshot exists)
    if (prev) {
      html += `<div class="col-block" style="margin-top:8px">
        <div class="col-hdr">
          <div class="col-hdr-label">
            <span class="col-dot dot-amber"></span>
            <span class="col-hdr-title">Changes</span>
          </div>
          <div class="col-hdr-date" style="font-size:16px;color:#475569">${formatDateLong(prev.date)} → ${formatDateLong(snap.date)}</div>
          <div class="col-hdr-actions">
            <span class="col-hdr-btn" style="background:transparent;border:none;color:#64748b;cursor:default">
              ${(() => {
                const cT = snapTeam, pT = _histTeam(prev.people);
                const dT = Math.round((cT - pT)*10)/10;
                const col = dT>0?'#059669':dT<0?'#dc2626':'#64748b';
                return `Team: <strong style="color:${col};font-family:'JetBrains Mono',monospace">${dT>0?'+':''}${dT}%</strong>`;
              })()}
            </span>
            <button class="col-hdr-btn" onclick="copyHistTable(this)" title="Copy this table as image">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              Copy
            </button>
            <button class="col-hdr-btn" onclick="exportHistTable(this,'changes-${snap.date}',false)" title="Download to PC">PC</button>
            <button class="col-hdr-btn" onclick="exportHistTable(this,'changes-${snap.date}',true)" title="Share to mobile">Mobile</button>
          </div>
        </div>
        <div style="overflow-x:auto">${_renderHistChangesTable(snap, prev)}</div>
      </div>`;
    }
  });

  wrap.innerHTML = html;
}

// ── init ───────────────────────────────────────────────────────────────────
function formatDateLong(iso) {
  if (!iso) return '—';
  const m = String(iso).match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return iso;
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  const d = new Date(`${m[1]}-${m[2]}-${m[3]}T00:00:00Z`);
  const wd = isNaN(d.getTime()) ? '' : days[d.getUTCDay()] + ' ';
  return `${wd}${parseInt(m[3])} ${months[parseInt(m[2])-1]} ${m[1]}`;
}

function formatDateTime(iso) {
  // iso can be "2026-05-27" or "2026-05-27T09:00:00+00:00"
  if (!iso) return '—';
  if (iso.length <= 10) return formatDateLong(iso);
  const d = new Date(iso);
  if (isNaN(d.getTime())) return formatDateLong(iso);
  const dateStr = formatDateLong(d.toISOString().slice(0,10));
  const timeStr = d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
  return `${dateStr} · ${timeStr}`;
}

function init() {
  const yr = document.getElementById('copy-year');
  if (yr) yr.textContent = new Date().getFullYear();
  document.getElementById('hdr-date').textContent = formatDateTime(REPORT.timestamp||REPORT.date);
  document.getElementById('ai-date').textContent  = REPORT.date||'';
  document.getElementById('tw-date').textContent  = formatDateTime(REPORT.timestamp||REPORT.date);
  document.getElementById('lw-date').textContent  = formatDateTime(REPORT.last_snap_time||REPORT.last_snap_date);
  const chDateEl = document.getElementById('ch-date');
  if (chDateEl) chDateEl.textContent = REPORT.last_snap_date
    ? `${formatDateLong(REPORT.last_snap_date)} → ${formatDateLong(REPORT.date)}`
    : 'No baseline yet';

  // Populate baseline picker
  populateBaselineSelector();

  // stats
  const tw=REPORT.team_total, lw=REPORT.team_last_week, d=REPORT.team_delta;
  const totalOv = REPORT.rows.reduce((s,r)=>s+(r.overdue||0),0);
  const isNew = d===null||d===undefined;
  const ds = pStyle(d,tw,isNew);

  document.getElementById('stats-row').innerHTML = `
    <div class="stat">
      <div class="lbl">This Period</div>
      <div class="val ${ds.pct==='pct-green'?'val-green':ds.pct==='pct-red'?'val-red':'val-blue'}">${tw}%</div>
      <div class="sub">Team completion</div>
    </div>
    <div class="stat">
      <div class="lbl">Last Period</div>
      <div class="val val-muted">${lw!==null&&lw!==undefined?lw+'%':'—'}</div>
      <div class="sub">Previous snapshot</div>
    </div>
    <div class="stat">
      <div class="lbl">Change</div>
      <div class="val ${!isNew&&d>0?'val-green':!isNew&&d<0?'val-red':'val-muted'}">${isNew?'—':d>0?'+'+d+'%':d+'%'}</div>
      <div class="sub">Period over period</div>
    </div>
    <div class="stat">
      <div class="lbl">Members</div>
      <div class="val val-blue">${REPORT.rows.length}</div>
      <div class="sub">Assigned</div>
    </div>
    <div class="stat">
      <div class="lbl">Total Tasks</div>
      <div class="val val-muted">${REPORT.grand_total||0}</div>
      <div class="sub">${REPORT.grand_done||0} done</div>
    </div>
    ${totalOv>0?`<div class="stat">
      <div class="lbl">Overdue</div>
      <div class="val val-red">${totalOv}</div>
      <div class="sub">Past due date</div>
    </div>`:''}
  `;

  // Analytics: donut + PMO health panel
  renderDonut();
  renderPMOPanel();

  // (The GitHub "last run" status chip was removed — the LIVE chip now shows
  // only the time since the live data was fetched in the browser.)

  // Overdue badge
  _refreshOverdueBadge();

  // Breaking-news ticker (recent task changes)
  _renderBreakingTicker();

  // Start the live freshness ticker + silent auto-reload watcher.
  _startLiveMode();

  // Auto-start live auto-refresh ONCE when the dashboard first opens, so the
  // page stays current on its own (pulls fresh Jira data every 10s in place).
  // Always on — there is no toggle. Guarded so repeated init() calls don't stack.
  if (GH_PROXY && !window._liveAutoStarted) {
    window._liveAutoStarted = true;
    startLiveAuto();   // immediate live pull + the 10s interval
  }

  // Load the configured weekly baseline day once so the "Auto · last X" label
  // matches the admin setting even before a snapshot lands on that day.
  if (!window._weeklyDayLoaded) { window._weeklyDayLoaded = true; _loadWeeklyDay(); }

  // AI text — hide the whole card on non-email runs (analysis empty).
  const aiEl = document.getElementById('ai-text');
  const aiCard = aiEl ? aiEl.closest('.ai-card') : null;
  const summary = (ANALYSIS.summary||'').trim();
  if (!summary) {
    if (aiCard) aiCard.style.display = 'none';
  } else {
    if (aiCard) aiCard.style.display = '';
    if (summary.includes('unavailable')||summary.includes('skipped')) {
      aiEl.innerHTML = `<span class="ai-err">${esc(summary)}</span>`;
    } else {
      aiEl.textContent = summary;
    }
  }

  // risk cards
  const risks = (ANALYSIS.risks||[]).filter(r=>r&&r.name);
  const riskSec = document.getElementById('risk-section');
  if (risks.length) {
    riskSec.style.display = '';
    document.getElementById('risk-grid').innerHTML = risks.map(r=>
      `<div class="risk-card">
        <div class="risk-name">${esc(r.name)}</div>
        <div class="risk-note">${esc(r.note||'')}</div>
        ${r.tip?`<div class="risk-tip">💡 ${esc(r.tip)}</div>`:''}
      </div>`
    ).join('');
  } else {
    riskSec.style.display = 'none';
    document.getElementById('risk-grid').innerHTML = '';
  }

  // weekly tables (apply persistent hidden list if loaded)
  const hide = hiddenPeople.size ? hiddenPeople : null;
  document.getElementById('tbl-tw').innerHTML = renderThisWeek(REPORT.rows, hide);
  document.getElementById('tbl-lw').innerHTML = renderLastWeek(REPORT.rows, hide);
  document.getElementById('tbl-ch').innerHTML = renderChanges(REPORT.rows, hide);
  buildHistTable();
  applyFilter('');
}
// init() is called from checkPw() after successful decrypt (not auto on DOMContentLoaded)

// ── refresh / save snapshot (use decrypted in-memory PAT) ──────────────────
function _dispatch(inputs, okMsg) {
  const repo = document.querySelector('meta[name=repo]')?.content||'';
  if (!GH_PAT) { toast('No token available — re-enter password.'); return; }
  if (!repo)   { toast('Repo not configured.'); return; }
  fetch(`https://api.github.com/repos/${repo}/actions/workflows/weekly.yml/dispatches`,{
    method:'POST',
    headers:{'Authorization':`Bearer ${GH_PAT}`,'Accept':'application/vnd.github+json','Content-Type':'application/json'},
    body: JSON.stringify({ref:'main', inputs})
  }).then(r=>{
    if(r.status===204) toast(okMsg);
    else r.json().then(d=>toast('Error: '+(d.message||r.status))).catch(()=>toast('Error: HTTP '+r.status));
  }).catch(e=>toast('Network error: '+e.message));
}

function triggerRefresh() { _triggerRefresh(false); }
function triggerRefreshAndEmail() {
  if (!confirm('Fetch latest from Jira and email both the full dashboard and a Changes-only image to the saved recipients?')) return;
  _triggerRefresh(true);
}
function _triggerRefresh(withEmail) {
  const repo = document.querySelector('meta[name=repo]')?.content||'';
  if (!GH_PAT) { toast('No token — re-enter password.'); return; }
  if (!repo)   { toast('Repo not configured.'); return; }
  // Prefer the saved-recipients list (data/email_recipients.json) so the
  // 'Refresh + Email' button sends to everyone configured in the modal,
  // not just whoever sits in the EMAIL_RECIPIENTS_DEFAULT secret.
  const recipients = withEmail && Array.isArray(SAVED_EMAILS) && SAVED_EMAILS.length
    ? SAVED_EMAILS.join(',')
    : '';
  _setRefreshLoading(true, withEmail ? 'Triggering refresh + email…' : 'Triggering…');
  fetch(`https://api.github.com/repos/${repo}/actions/workflows/weekly.yml/dispatches`,{
    method:'POST',
    headers:{'Authorization':`Bearer ${GH_PAT}`,'Accept':'application/vnd.github+json','Content-Type':'application/json'},
    body: JSON.stringify({ref:'main', inputs:{
      save_history:'false',
      send_email: withEmail ? 'true' : 'false',
      force_weekly:'false',
      recipients,              // saved list if present, else fallback to secret
      attachment_path: '',     // empty → workflow attaches dashboard_full + changes_only
    }})
  }).then(r=>{
    if (r.status === 204) {
      _setRefreshLoading(true, withEmail ? 'Fetching + emailing…' : 'Fetching from Jira…');
      _watchWorkflowAndReload();
      if (withEmail) toast('✓ Refresh + email queued. Recipients get 2 images: full dashboard + Changes-only.');
    } else {
      _setRefreshLoading(false);
      r.json().then(d=>toast('Error: '+(d.message||r.status))).catch(()=>toast('Error: HTTP '+r.status));
    }
  }).catch(e=>{
    _setRefreshLoading(false);
    toast('Network error: '+e.message);
  });
}

function _setRefreshLoading(loading, txt) {
  const btn = document.getElementById('refresh-btn');
  const icon = document.getElementById('refresh-icon');
  const label = document.getElementById('refresh-label');
  const prog = document.getElementById('refresh-progress');
  const progTxt = document.getElementById('refresh-progress-txt');
  if (loading) {
    btn.disabled = true;
    btn.classList.add('btn-loading');
    icon.classList.add('spinner');
    label.textContent = 'Refreshing…';
    prog.classList.add('show');
    if (txt) progTxt.textContent = txt;
  } else {
    btn.disabled = false;
    btn.classList.remove('btn-loading');
    icon.classList.remove('spinner');
    label.textContent = 'Refresh';
    prog.classList.remove('show');
  }
}

async function _watchWorkflowAndReload() {
  const repo = document.querySelector('meta[name=repo]')?.content||'';
  if (!repo) return;
  let attempts = 0;
  const maxAttempts = 40;  // ~3.5 min total
  let startRunId = null;

  // First, find the latest run that we just triggered
  try {
    await new Promise(r => setTimeout(r, 4000));   // workflow registers ~3s later
    const r = await fetch(`https://api.github.com/repos/${repo}/actions/runs?per_page=3`,{
      headers:{'Authorization':`Bearer ${GH_PAT}`,'Accept':'application/vnd.github+json'}
    });
    const d = await r.json();
    startRunId = d.workflow_runs?.[0]?.id;
  } catch(e){}

  const check = async () => {
    attempts++;
    try {
      const r = await fetch(`https://api.github.com/repos/${repo}/actions/runs/${startRunId||''}`,{
        headers:{'Authorization':`Bearer ${GH_PAT}`,'Accept':'application/vnd.github+json'}
      });
      if (r.ok) {
        const run = await r.json();
        const elapsed = Math.round((Date.now() - new Date(run.created_at).getTime())/1000);
        const txt = document.getElementById('refresh-progress-txt');
        if (run.status === 'queued') txt.textContent = `Queued · ${elapsed}s`;
        else if (run.status === 'in_progress') txt.textContent = `Building · ${elapsed}s`;
        if (run.status === 'completed') {
          if (run.conclusion === 'success') {
            txt.textContent = 'Done — reloading…';
            toast('✓ Refresh complete. Reloading page…');
            setTimeout(()=>location.reload(), 1200);
          } else {
            _setRefreshLoading(false);
            toast('Refresh failed: '+run.conclusion);
          }
          return;
        }
      }
    } catch(e){}
    if (attempts >= maxAttempts) {
      _setRefreshLoading(false);
      toast('Timed out — please reload manually.');
      return;
    }
    setTimeout(check, 5000);
  };
  check();
}

// ── Delete a single history snapshot (separate password) ───────────────────
async function _sha256Hex(s) {
  const buf = new TextEncoder().encode(s);
  const h = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2,'0')).join('');
}
async function deleteWeekSnapshot(date) {
  const expected = (document.querySelector('meta[name=delete-hash]')?.content||'').trim();
  if (!expected) {
    toast('Delete is disabled — DELETE_PASSWORD_HASH is not configured.');
    return;
  }
  const pw = prompt(`Enter the DELETE password to remove the snapshot dated ${date}.\n\nThis is a separate password from the site login.`);
  if (pw === null) return;
  if (!pw) { toast('Cancelled — password is empty.'); return; }
  const got = await _sha256Hex(pw);
  if (got !== expected.toLowerCase()) {
    toast('✗ Wrong delete password.');
    return;
  }
  if (!confirm(`Permanently delete the ${date} snapshot from history? This cannot be undone.`)) return;
  if (!GH_PAT) { toast('No GitHub token available — cannot save.'); return; }
  const repo = document.querySelector('meta[name=repo]')?.content||'';
  if (!repo) { toast('No repo configured.'); return; }
  const sitePw = sessionStorage.getItem('pw_cache');
  if (!sitePw) { toast('Session expired — reload and re-enter the password.'); return; }
  try {
    const headers = {'Authorization': 'token '+GH_PAT, 'Accept':'application/vnd.github+json'};
    // History is stored ENCRYPTED at rest (data/history.json.enc). Read it,
    // decrypt with the cached site password, filter, re-encrypt, write back.
    const url = `https://api.github.com/repos/${repo}/contents/data/history.json.enc`;
    const g = await fetch(url, {headers, cache:'no-store'});
    if (!g.ok) throw new Error('Read failed HTTP '+g.status);
    const meta = await g.json();
    const blob = JSON.parse(atob(meta.content.replace(/\n/g,'')));
    const cur  = await decryptBlob(blob, sitePw);
    const next = cur.filter(s => s.date !== date);
    if (next.length === cur.length) { toast('Snapshot not found in history.'); return; }
    const reEnc = await encryptBlob(next, sitePw);
    const body = {
      message: `Delete history snapshot ${date}`,
      content: btoa(unescape(encodeURIComponent(JSON.stringify(reEnc) + '\n'))),
      sha: meta.sha,
    };
    const p = await fetch(url, {method:'PUT', headers, body: JSON.stringify(body)});
    if (!p.ok) throw new Error('Write failed HTTP '+p.status+' — '+(await p.text()).slice(0,120));
    // Update in-memory and re-render
    REPORT.history = next;
    if (_ORIGINAL_REPORT) _ORIGINAL_REPORT.history = next;
    buildHistTable();
    populateBaselineSelector();
    toast(`✓ Snapshot ${date} deleted. Next scheduled build will see the update.`);
  } catch(e) {
    console.error('[delete]', e);
    toast('✗ Delete failed: '+e.message);
  }
}

// ── LIVE mode: ticking freshness + silent auto-reload when new build lands ─
let _LIVE_INITIAL_LM = null;     // Last-Modified of docs/index.html at page load
let _LIVE_REFRESHING = false;

function _startLiveMode() {
  // Tick the "X seconds ago" chip every second.
  _liveTick();
  // init() may run more than once (e.g. after a live refresh) — only ever
  // install these intervals once so they don't stack.
  if (window._liveModeStarted) return;
  window._liveModeStarted = true;
  setInterval(_liveTick, 1000);
  // NOTE: the old silent full-page reload (poll index.html's Last-Modified,
  // then location.reload() when the bot rebuilds) is intentionally DISABLED —
  // the dashboard now updates in place via refreshLive()/auto-refresh, so a
  // disruptive whole-page reload every time the bot commits is no longer wanted.
  // setInterval(_livePoll, 15_000);
  // Capture the baseline Last-Modified for comparison.
  fetch(window.location.href, {method:'HEAD', cache:'no-store'})
    .then(r => { _LIVE_INITIAL_LM = r.headers.get('last-modified'); })
    .catch(()=>{});
}

function _liveTick() {
  const ago = document.getElementById('live-ago');
  const chip = document.getElementById('live-chip');
  if (!ago || !chip) return;
  // While a live pull is in progress the chip is red "loading…" — don't clobber it.
  if (chip.classList.contains('loading')) return;
  // Count from the moment the LIVE data was fetched in the browser — NOT the
  // GitHub build/snapshot time. Before the first live fetch lands, show
  // "just now" rather than a stale "2h ago" from the last GitHub build.
  if (!window._LIVE_FETCHED_AT) { ago.textContent = 'just now'; chip.classList.remove('warm','stale'); return; }
  const ageMs = Date.now() - window._LIVE_FETCHED_AT;
  const s = Math.max(0, Math.floor(ageMs/1000));
  let text;
  if (s < 5)       text = 'just now';
  else if (s < 60) text = `${s}s ago`;
  else if (s < 3600) {
    const m = Math.floor(s/60), r = s%60;
    text = r ? `${m}m ${r}s ago` : `${m}m ago`;
  } else {
    text = `${Math.floor(s/3600)}h ago`;
  }
  ago.textContent = text;
  chip.classList.remove('warm','stale');
  if      (s >= 300) chip.classList.add('stale');    // > 5 min
  else if (s >= 120) chip.classList.add('warm');     // > 2 min
}

async function _livePoll() {
  if (_LIVE_REFRESHING) return;
  if (document.visibilityState !== 'visible') return;
  // Don't reload if any modal is open — the user is interacting with it.
  if (document.querySelector('.modal-overlay:not(.hidden)')) return;
  try {
    const r = await fetch(window.location.href, {method:'HEAD', cache:'no-store'});
    const lm = r.headers.get('last-modified');
    if (!lm || !_LIVE_INITIAL_LM) { _LIVE_INITIAL_LM = lm; return; }
    if (new Date(lm).getTime() > new Date(_LIVE_INITIAL_LM).getTime() + 2000) {
      // New build is up. Soft-reload to pick it up.
      _LIVE_REFRESHING = true;
      const chip = document.getElementById('live-chip');
      if (chip) chip.classList.add('refreshing');
      // Brief delay so user sees the "refreshing…" hint before reload.
      setTimeout(() => location.reload(), 400);
    }
  } catch(e) { /* network blip — ignore, try again next tick */ }
}

// ── Latest workflow run (public, no auth) ──────────────────────────────────
async function _loadLastRun() {
  const repo = document.querySelector('meta[name=repo]')?.content||'';
  const chip = document.getElementById('last-run-chip');
  const txt  = document.getElementById('lr-txt');
  if (!chip || !txt) return;
  // Always provide a click-through to GitHub Actions even if the API call fails.
  if (repo) chip.dataset.url = `https://github.com/${repo}/actions/workflows/weekly.yml`;
  try {
    if (!repo) throw new Error('repo meta missing');
    // Authenticate with GH_PAT when available (5000 req/hr vs 60 anon).
    const headers = GH_PAT ? {'Authorization':'token '+GH_PAT, 'Accept':'application/vnd.github+json'} : {};
    // Pull a handful so we can filter out the cron_ping pings that just
    // exit early (those are visible in the admin log but pollute the chip).
    const r = await fetch(`https://api.github.com/repos/${repo}/actions/workflows/weekly.yml/runs?per_page=15`,
                          {cache:'no-store', headers});
    if (r.status === 403 || r.status === 429) {
      txt.textContent = '⚠ Rate-limited';
      chip.classList.add('fail');
      return;
    }
    if (!r.ok) throw new Error('HTTP '+r.status);
    const j = await r.json();
    const all = j.workflow_runs || [];
    // Keep only "real" runs: schedule, workflow_dispatch, or a
    // repository_dispatch that actually built the report (duration ≥ 25s;
    // the decide-only short-circuit is ~5-10s).
    const real = all.filter(rn => {
      if (rn.event === 'schedule' || rn.event === 'workflow_dispatch') return true;
      if (rn.event === 'repository_dispatch') {
        const dur = (new Date(rn.updated_at) - new Date(rn.created_at)) / 1000;
        return dur >= 25;
      }
      return false;
    });
    const run = real[0] || null;
    if (!run) { txt.textContent = 'No update yet'; return; }
    chip.dataset.url = run.html_url;
    chip.classList.remove('ok','fail','run');
    let statusLabel = run.conclusion || run.status;
    if (run.status === 'completed' && run.conclusion === 'success') chip.classList.add('ok');
    else if (run.status === 'completed' && run.conclusion === 'failure') chip.classList.add('fail');
    else if (run.status !== 'completed') chip.classList.add('run');
    const when = new Date(run.updated_at);
    const elapsed = Math.round((Date.now() - when.getTime())/60000);
    const ago = elapsed < 1 ? 'just now'
              : elapsed < 60 ? `${elapsed}m ago`
              : elapsed < 1440 ? `${Math.round(elapsed/60)}h ago`
              : `${Math.round(elapsed/1440)}d ago`;
    const icon = run.event === 'schedule' ? '⏰' : '🖱';
    txt.textContent = `${icon} Updated · ${ago}`;
    chip.title = `Last updated ${when.toLocaleString()}`;
  } catch(e){
    txt.textContent = '⚠ unreachable';
    chip.classList.add('fail');
  }
}

// ── Persistent hidden list (saved to data/hidden_people.json) ──────────────
// Real-time strategy: get the latest commit SHA on `main`, then fetch the file
// AT THAT SHA. Content pinned to a SHA is immutable in Git → GitHub never
// caches it → guaranteed fresh on every load, no 60s API cache wait.
async function _loadHiddenListRemote() {
  const repo = document.querySelector('meta[name=repo]')?.content||'';
  if (!repo) return;

  let list = null;
  const cb = Date.now();

  // STEP 1: latest SHA on main
  let sha = null;
  try {
    const headers = {'Accept':'application/vnd.github+json'};
    if (GH_PAT) headers['Authorization'] = `Bearer ${GH_PAT}`;
    const r = await fetch(`https://api.github.com/repos/${repo}/commits/main?t=${cb}`,
                          {headers, cache:'no-store'});
    if (r.ok) {
      const j = await r.json();
      sha = j.sha;
      console.log('[hidden] latest main SHA:', sha?.slice(0,7));
    }
  } catch(e) { console.warn('[hidden] SHA fetch failed:', e); }

  // STEP 2: fetch the ENCRYPTED store at that SHA (immutable → always fresh)
  // and decrypt with the cached site password. (Was plaintext hidden_people.json;
  // now data/hidden_people.json.enc.)
  if (sha) {
    const dec = await _loadEncStore('hidden_people.json', sha);
    if (Array.isArray(dec)) { list = dec; console.log('[hidden] decrypted', list); }
  }

  // STEP 3: fallback — latest encrypted store (no SHA pin)
  if (!Array.isArray(list)) {
    const dec = await _loadEncStore('hidden_people.json');
    if (Array.isArray(dec)) list = dec;
  }

  // STEP 4: apply
  if (Array.isArray(list)) {
    hiddenPeople.clear();
    list.forEach(n => hiddenPeople.add(n));
    console.log(`[hidden] applied ${list.length} hidden people:`, list);
  } else {
    console.warn('[hidden] no list loaded — leaving hiddenPeople as-is');
  }
  _updateHiddenIndicator();
}

function _updateHiddenIndicator() {
  const el = document.getElementById('hidden-indicator');
  if (!el) return;
  if (hiddenPeople.size > 0) {
    el.style.display = 'inline-flex';
    const txt = el.querySelector('.hi-count');
    if (txt) txt.textContent = hiddenPeople.size;
  } else {
    el.style.display = 'none';
  }
}

function _rerenderTables() {
  const hide = hiddenPeople.size ? hiddenPeople : null;
  // Recompute Last Period team total against the currently hidden list
  // (the server-side value was frozen at save time).
  if (typeof setBaseline === 'function' && REPORT && (REPORT.history||[]).length) {
    const cur = REPORT.last_snap_date || 'auto';
    setBaseline(cur);
    // setBaseline triggers init() which re-renders; bail to avoid double work.
    return;
  }
  const tw = document.getElementById('tbl-tw');
  const lw = document.getElementById('tbl-lw');
  const ch = document.getElementById('tbl-ch');
  if (tw) tw.innerHTML = renderThisWeek(REPORT.rows, hide);
  if (lw) lw.innerHTML = renderLastWeek(REPORT.rows, hide);
  if (ch) ch.innerHTML = renderChanges(REPORT.rows, hide);
  if (typeof renderDonut === 'function') renderDonut();
  if (typeof renderPMOPanel === 'function') renderPMOPanel();
  if (typeof buildHistTable === 'function' && document.getElementById('tbl-hist')) buildHistTable();
  applyFilter(document.getElementById('name-filter')?.value || '');
  _updateHiddenIndicator();
  _refreshOverdueBadge();
  _renderBreakingTicker();
}

// Pending custom attachment for the email modal — set by exportAndEmail
let _PENDING_EMAIL_CANVAS = null;
let _PENDING_EMAIL_LABEL  = '';

// Lazy-load html2canvas one time
function _ensureHtml2Canvas() {
  if (window.html2canvas) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = 'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';
    s.onload = () => resolve();
    s.onerror = () => reject(new Error('Failed to load html2canvas'));
    document.head.appendChild(s);
  });
}

// Capture the live DOM sections (pixel-match to what's on screen).
// Stitches them into ONE canvas vertically, Dashboard always on top.
async function _captureLiveDashboard(secs) {
  await _ensureHtml2Canvas();

  // Ensure Weekly tab is showing for tables (in case user is on History tab)
  if ((secs.tw || secs.lw || secs.ch) && currentTab !== 'weekly') {
    showTab('weekly', document.querySelector('.tab-btn'));
    await new Promise(r => setTimeout(r, 100));
  }

  const targets = [];

  // Dashboard always first (on top)
  if (secs.dash) {
    const dash = document.getElementById('analytics-card');
    if (dash) {
      const wasCollapsed = dash.classList.contains('collapsed');
      if (wasCollapsed) dash.classList.remove('collapsed');
      targets.push({el:dash, label:'Dashboard', restore: wasCollapsed});
    }
  }

  const pickBlock = (id) => {
    const e = document.getElementById(id);
    return e ? e.closest('.col-block') : null;
  };
  if (secs.tw) { const e = pickBlock('tbl-tw'); if (e) targets.push({el:e, label:'This Week'}); }
  if (secs.lw) { const e = pickBlock('tbl-lw'); if (e) targets.push({el:e, label:'Last Week'}); }
  if (secs.ch) { const e = pickBlock('tbl-ch'); if (e) targets.push({el:e, label:'Changes'});   }

  if (!targets.length) return null;

  // Hide topbar buttons during capture (just in case)
  document.body.classList.add('capturing');
  await new Promise(r => setTimeout(r, 100));

  // Capture each in turn
  const shots = [];
  try {
    for (const t of targets) {
      const cv = await _h2c(t.el);
      shots.push({canvas: cv, label: t.label});
      if (t.restore) t.el.classList.add('collapsed');
    }
  } finally {
    document.body.classList.remove('capturing');
  }

  // Stitch vertically
  const PAD = 36, GAP = 22;
  const TITLE_H = 84;
  const W = Math.max(...shots.map(s => s.canvas.width)) + PAD*2;
  const stitchedH = shots.reduce((s,c) => s + c.canvas.height + GAP, 0) - GAP;
  const H = PAD + TITLE_H + stitchedH + PAD;

  const cv = document.createElement('canvas');
  cv.width = W; cv.height = H;
  const ctx = cv.getContext('2d');

  // Soft cloud-AI background gradient
  const bg = ctx.createLinearGradient(0, 0, W, H);
  bg.addColorStop(0,   '#fbfaf7');
  bg.addColorStop(0.5, '#f3f6fb');
  bg.addColorStop(1,   '#f7f6f1');
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, W, H);

  // Header
  ctx.fillStyle = '#0f172a';
  ctx.font = 'bold 38px Inter, Arial, sans-serif';
  ctx.textAlign = 'left';
  ctx.fillText('FIBTMP Progress Report', PAD, PAD + 32);
  ctx.fillStyle = '#64748b';
  ctx.font = '20px "JetBrains Mono", monospace';
  ctx.fillText(`${REPORT.date} ${_nowHM()} · Project Management Office`, PAD, PAD + 62);

  // Sections
  let y = PAD + TITLE_H;
  for (const item of shots) {
    const x = Math.floor((W - item.canvas.width) / 2);
    ctx.drawImage(item.canvas, x, y);
    y += item.canvas.height + GAP;
  }
  return cv;
}

// "Send by Email" inside the Export modal — captures live DOM matching the
// Weekly tab look, then opens the email modal for recipient + send.
async function exportAndEmail() {
  const secs = {};
  document.querySelectorAll('#exp-sections input[type=checkbox]').forEach(cb=>{
    secs[cb.dataset.sec] = cb.checked;
  });
  if (!secs.tw && !secs.lw && !secs.ch && !secs.dash) {
    toast('Pick at least one section.');
    return;
  }
  toast('Capturing dashboard view…');
  try {
    const cv = await _captureLiveDashboard(secs);
    if (!cv) { toast('Nothing to capture.'); return; }
    _PENDING_EMAIL_CANVAS = cv;
    const parts = [];
    if (secs.dash) parts.push('Dashboard');
    if (secs.tw)   parts.push('This Week');
    if (secs.lw)   parts.push('Last Week');
    if (secs.ch)   parts.push('Changes');
    _PENDING_EMAIL_LABEL = parts.join(' + ');
    closeModal('export-modal');
    openEmailModal();
  } catch(e) {
    toast('Capture failed: '+e.message);
    console.error(e);
  }
}

// ── Email recipients (persisted in data/email_recipients.json) ─────────────
let SAVED_EMAILS = [];      // loaded from repo
let SELECTED_EMAILS = new Set();  // for the current send

async function _loadEmailListRemote() {
  // Stored encrypted at rest (data/email_recipients.json.enc) — contains emails.
  const list = await _loadEncStore('email_recipients.json');
  if (Array.isArray(list)) {
    SAVED_EMAILS = list;
    console.log('[email] saved recipients:', SAVED_EMAILS.length);
  }
}

function openEmailModal() {
  // Set the "what will be attached" info banner
  const info = document.getElementById('email-attach-info');
  if (info) {
    if (_PENDING_EMAIL_CANVAS) {
      info.innerHTML = `📎 <strong>Custom attachment</strong>: ${esc(_PENDING_EMAIL_LABEL)} — built from your Export selections.`;
      info.style.color = '#1e40af';
      info.style.background = '#dbeafe';
      info.style.borderRadius = '8px';
      info.style.padding = '8px 12px';
      info.style.border = '1px solid #bfdbfe';
    } else {
      info.innerHTML = 'Sends the default full report PNG. Use the <strong>Export Image</strong> button if you want to email only specific sections.';
      info.style.color = '#64748b';
      info.style.background = '';
      info.style.padding = '';
      info.style.border = '';
    }
  }
  // Refresh saved list, then render
  _loadEmailListRemote().then(() => {
    SELECTED_EMAILS = new Set(SAVED_EMAILS);
    _renderEmailModal();
    openModal('email-modal');
  });
}

function _renderEmailModal() {
  const wrap = document.getElementById('email-saved-list');
  wrap.innerHTML = '';
  if (!SAVED_EMAILS.length) {
    wrap.innerHTML = '<div style="font-size:12px;color:#94a3b8">No saved recipients yet — add one below.</div>';
  } else {
    SAVED_EMAILS.forEach(em => {
      const btn = document.createElement('button');
      btn.className = 'vis-btn' + (SELECTED_EMAILS.has(em) ? '' : ' hidden-person');
      btn.innerHTML = (SELECTED_EMAILS.has(em) ? '✓' : '✕') + ' ' + esc(em);
      btn.onclick = () => {
        if (SELECTED_EMAILS.has(em)) SELECTED_EMAILS.delete(em);
        else SELECTED_EMAILS.add(em);
        _renderEmailModal();
      };
      // Add "remove from list" small button
      btn.title = 'Click to toggle. To permanently remove, use the saved list management.';
      wrap.appendChild(btn);
    });
  }
  // Selected summary
  const arr = [...SELECTED_EMAILS];
  document.getElementById('email-count').textContent = arr.length;
  document.getElementById('email-selected-display').textContent =
    arr.length ? arr.join(', ') : '(none selected — pick at least one)';
  const btn = document.getElementById('send-email-btn');
  if (btn) btn.disabled = arr.length === 0;
}

function addEmailToSelection() {
  const inp = document.getElementById('email-new-inp');
  const v = (inp.value || '').trim();
  if (!v || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) {
    toast('Enter a valid email address.'); return;
  }
  SELECTED_EMAILS.add(v);
  inp.value = '';
  _renderEmailModal();
}

async function saveEmailToList() {
  const repo = document.querySelector('meta[name=repo]')?.content||'';
  if (!GH_PAT) { toast('No token — re-enter password.'); return; }
  const inp = document.getElementById('email-new-inp');
  const v = (inp.value || '').trim();
  if (!v || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) {
    toast('Enter a valid email address.'); return;
  }
  if (SAVED_EMAILS.includes(v)) {
    toast('Already in saved list.');
    SELECTED_EMAILS.add(v);
    inp.value = '';
    _renderEmailModal();
    return;
  }
  const newList = [...SAVED_EMAILS, v];
  try {
    // Stored encrypted at rest (data/email_recipients.json.enc) — contains emails.
    const ok = await _saveEncStore('email_recipients.json', newList, `Add email recipient ${v}`);
    if (ok) {
      SAVED_EMAILS = newList;
      SELECTED_EMAILS.add(v);
      inp.value = '';
      _renderEmailModal();
      toast(`✓ Saved ${v} to recipient list.`);
    }
  } catch(e) { toast('Save failed: '+e.message); }
}

async function sendEmailNow() {
  const repo = document.querySelector('meta[name=repo]')?.content||'';
  if (!GH_PAT) { toast('No token — re-enter password.'); return; }
  const arr = [...SELECTED_EMAILS];
  if (!arr.length) { toast('Pick at least one recipient.'); return; }
  const to = arr.join(',');
  const btn = document.getElementById('send-email-btn');
  btn.disabled = true;

  let attachmentPath = '';

  // If user came from Export modal with a custom canvas, upload it first
  if (_PENDING_EMAIL_CANVAS) {
    btn.innerHTML = 'Uploading image…';
    try {
      const dataUrl = _PENDING_EMAIL_CANVAS.toDataURL('image/png');
      const b64 = dataUrl.split(',')[1];
      const ts = Date.now();
      const path = `data/temp/email-${ts}.png`;
      const headers = {'Authorization':`Bearer ${GH_PAT}`,'Accept':'application/vnd.github+json','Content-Type':'application/json'};
      const putRes = await fetch(`https://api.github.com/repos/${repo}/contents/${path}`, {
        method:'PUT', headers,
        body: JSON.stringify({
          message: `temp email attachment (${_PENDING_EMAIL_LABEL||'export'})`,
          content: b64,
        })
      });
      if (!putRes.ok) {
        const j = await putRes.json();
        throw new Error('Upload failed: '+(j.message||putRes.status));
      }
      attachmentPath = path;
      console.log('[email] uploaded custom attachment:', path);
    } catch(e) {
      btn.disabled=false; btn.innerHTML='📧 Send Now';
      toast(e.message);
      return;
    }
  }

  // Trigger workflow with our (possibly custom) attachment path
  btn.innerHTML = 'Triggering workflow…';
  try {
    const r = await fetch(`https://api.github.com/repos/${repo}/actions/workflows/weekly.yml/dispatches`, {
      method:'POST',
      headers:{'Authorization':`Bearer ${GH_PAT}`,'Accept':'application/vnd.github+json','Content-Type':'application/json'},
      body: JSON.stringify({ref:'main', inputs:{
        save_history:'false',
        send_email:'true',
        recipients: to,
        force_weekly:'false',
        attachment_path: attachmentPath,
      }})
    });
    if (r.status === 204) {
      const what = _PENDING_EMAIL_LABEL ? ` (${_PENDING_EMAIL_LABEL})` : '';
      toast(`✓ Email triggered to ${arr.length} recipient(s)${what} — arrives in ~45s.`);
      _PENDING_EMAIL_CANVAS = null;
      _PENDING_EMAIL_LABEL = '';
      closeModal('email-modal');
    } else {
      const j = await r.json();
      toast('Error: '+(j.message||r.status));
    }
  } catch(e) {
    toast('Network error: '+e.message);
  } finally {
    btn.disabled = false; btn.innerHTML = '📧 Send Now';
  }
}

async function saveHiddenList() {
  const btn = document.getElementById('save-hidden-btn');
  if (btn) btn.disabled = true;
  const list = [...hiddenPeople].sort();
  try {
    // Stored encrypted at rest (data/hidden_people.json.enc) — contains names.
    const ok = await _saveEncStore('hidden_people.json', list,
                 `Update hidden people list (${list.length} hidden)`);
    if (ok) {
      _rerenderTables();   // immediate local update
      toast(`✓ Saved (${list.length} hidden) — others see it on their next reload.`);
    }
  } catch(e) {
    toast('Save failed: '+e.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function saveSnapshotNow() {
  if (!confirm('Save current data as a history snapshot? This adds today to the History tab and enables Compare Periods.')) return;
  toast('Saving snapshot…');
  _dispatch({save_history:'true', send_email:'false'},
            '✓ Snapshot scheduled — appears in History tab in ~60 seconds.');
}

// ── export Excel ───────────────────────────────────────────────────────────
function exportExcel() {
  toast('Generating Excel…');
  const s=document.createElement('script');
  s.src='https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js';
  s.onload=()=>{
    const wb = XLSX.utils.book_new();
    const h1=['Owner','Total','Open','In Progress','Waiting For Approval','Overdue','Completed','Done %','Last Period %','Change'];
    const d1=REPORT.rows.map(r=>[r.owner,r.total,r.open,r.in_progress,
      r.waiting_for_approval,r.overdue,r.completed,r.this_week+'%',
      r.last_week!==null?r.last_week+'%':'N/A',
      r.delta!==null?(r.delta>0?'+':'')+r.delta+'%':'NEW']);
    XLSX.utils.book_append_sheet(wb,XLSX.utils.aoa_to_sheet([h1,...d1]),'This Week');

    const h2=['Owner','Total','Open','In Progress','Waiting For Approval','Overdue','Completed','Done %'];
    const d2=REPORT.rows.filter(r=>r.last_week!==null).map(r=>[
      r.owner,r.last_total,r.last_open,r.last_in_progress,r.last_wfa,r.last_overdue,r.last_completed,r.last_week+'%']);
    XLSX.utils.book_append_sheet(wb,XLSX.utils.aoa_to_sheet([h2,...d2]),'Last Week');

    const h3=['Owner','Change %','Total','Open','In Progress','WFA','Overdue','Done'];
    const d3=REPORT.rows.map(r=>{
      const isNew=r.delta===null; const sym=v=>isNew?'NEW':(v>=0?'+':'')+v;
      return [r.owner, isNew?'NEW':(r.delta>=0?'+':'')+r.delta+'%',
        sym(r.total-(r.last_total||0)), sym(r.open-(r.last_open||0)),
        sym(r.in_progress-(r.last_in_progress||0)),
        sym(r.waiting_for_approval-(r.last_wfa||0)),
        sym(r.overdue-(r.last_overdue||0)), sym(r.completed-(r.last_completed||0))];
    });
    XLSX.utils.book_append_sheet(wb,XLSX.utils.aoa_to_sheet([h3,...d3]),'Changes');

    const hist=REPORT.history||[];
    if(hist.length){
      const pp=[...new Set(hist.flatMap(s=>Object.keys(s.people||{})))].sort();
      const hh=['Date','Team %',...pp];
      const dh=hist.slice().reverse().map(s=>[s.date,s.team_total+'%',
        ...pp.map(p=>{const v=(s.people||{})[p];return v===undefined?'':(typeof v==='object'?v.pct+'%':v+'%');})]);
      XLSX.utils.book_append_sheet(wb,XLSX.utils.aoa_to_sheet([hh,...dh]),'History');
    }
    XLSX.writeFile(wb,`progress-${REPORT.date}.xlsx`);
    toast('✓ Excel downloaded.');
  };
  s.onerror=()=>toast('Failed to load XLSX library.');
  document.head.appendChild(s);
}

// ── Executive Summary (PPTX) ────────────────────────────────────────────
// A ready-to-present 8-slide deck for steering committee / leadership.
// Data pulled from the same computed values as the on-screen PMO panel
// so the deck always matches what's on the dashboard.
function _computePMOSummary() {
  const rows = REPORT.rows.filter(r => r.owner !== 'Unassigned' && (r.total||0) > 0 && !hiddenPeople.has(r.owner));
  const rag = {green:[], amber:[], red:[]};
  rows.forEach(r => {
    const pct = r.this_week || 0;
    const ov  = r.overdue || 0;
    const d   = r.delta;
    if (pct >= 80 && ov <= 1) rag.green.push(r);
    else if (pct < 50 || ov >= 4 || (d === 0 && pct < 50)) rag.red.push(r);
    else rag.amber.push(r);
  });
  const gTotal = rows.reduce((s,r)=>s+(r.total||0),0);
  const gDone  = rows.reduce((s,r)=>s+(r.completed||0),0);
  const gIP    = rows.reduce((s,r)=>s+(r.in_progress||0),0);
  const gWFA   = rows.reduce((s,r)=>s+(r.waiting_for_approval||0),0);
  const gOv    = rows.reduce((s,r)=>s+(r.overdue||0),0);
  const completion  = gTotal ? +(gDone/gTotal*100).toFixed(1) : 0;
  const overdueRate = gTotal ? +(gOv/gTotal*100).toFixed(1) : 0;
  const wipRatio     = gTotal ? +(gIP/gTotal*100).toFixed(1) : 0;

  const watchlistFull = rows.slice().map(r => {
    const reasons = [];
    const pct = r.this_week||0, ov = r.overdue||0, d = r.delta;
    if (ov >= 4) reasons.push(`${ov} overdue`);
    else if (ov >= 2) reasons.push(`${ov} overdue`);
    else if (ov === 1) reasons.push(`1 overdue`);
    if (pct < 30) reasons.push(`only ${pct}%`);
    else if (pct < 50) reasons.push(`${pct}%`);
    if (d !== null && d !== undefined && d < -5) reasons.push(`${d}% WoW`);
    if (pct === 0 && (r.total||0) > 2) reasons.push('no progress');
    const score = ov*15 + Math.max(0,50-pct) + (d<0?Math.abs(d)*2:0);
    return {...r, _reasons: reasons, _score: score};
  }).filter(r => r._reasons.length > 0)
    .sort((a,b) => b._score - a._score);

  const wins = rows.slice()
    .filter(r => (r.this_week||0) >= 80 || (r.delta||0) >= 10)
    .sort((a,b) => (b.this_week||0) - (a.this_week||0))
    .slice(0, 8);

  // Per-owner breakdown sorted best → worst for the team slide
  const teamRows = rows.slice().sort((a,b) => (b.this_week||0) - (a.this_week||0));

  return { rag, gTotal, gDone, gIP, gWFA, gOv, completion, overdueRate, wipRatio,
           watchlist: watchlistFull, wins, teamRows, total: rows.length };
}

async function exportExecutivePPTX() {
  if (!REPORT) return;
  toast('Building executive summary…');

  const loadPptxGen = () => new Promise((resolve, reject) => {
    if (window.PptxGenJS) return resolve();
    const s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/npm/pptxgenjs@3.12.0/dist/pptxgen.bundle.js';
    s.onload = resolve;
    s.onerror = () => reject(new Error('Failed to load PPTX library.'));
    document.head.appendChild(s);
  });

  try {
    await loadPptxGen();

    const S = _computePMOSummary();
    const projectName = (REPORT.jira_base_url||'').includes('fibtask') ? 'FIBTMP' : 'PMO';
    const reportDate = REPORT.date || '';
    const now = new Date();
    const generatedAt = now.toLocaleString('en-GB', {day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'});
    const risks = (ANALYSIS && ANALYSIS.risks || []).filter(r=>r&&r.name).slice(0,6);
    const summaryText = (ANALYSIS && ANALYSIS.summary || '').trim();

    // ── Colour palette ──
    const NAVY   = '0F2554';
    const NAVY2  = '1F4E78';
    const ACCENT = '2563EB';
    const GREEN  = '16A34A';
    const AMBER  = 'D97706';
    const ORANGE = 'EA580C';
    const RED    = 'DC2626';
    const TEAL   = '0891B2';
    const PURPLE = '7C3AED';
    const SLATE  = '475569';
    const MUTED  = '94A3B8';
    const LIGHT  = 'F1F5F9';
    const WHITE  = 'FFFFFF';
    const DARKGRAY = '1E293B';

    const pptx = new PptxGenJS();
    pptx.defineLayout({ name:'WIDE', width:13.33, height:7.5 });
    pptx.layout = 'WIDE';
    pptx.author  = 'PMO Dashboard';
    pptx.subject = `${projectName} Executive Summary`;
    pptx.title   = `${projectName} Executive Summary – ${reportDate}`;

    // ── Helpers ────────────────────────────────────────────────────────────
    const addHeader = (slide, title, subtitle, accentColor) => {
      // Left stripe
      slide.addShape('rect', { x:0, y:0, w:0.22, h:7.5, fill:{color:accentColor||ACCENT} });
      // Top bar
      slide.addShape('rect', { x:0.22, y:0, w:13.11, h:0.9, fill:{color:NAVY} });
      slide.addText(title, { x:0.45, y:0.1, w:10, h:0.72, fontSize:22, bold:true, color:WHITE, fontFace:'Arial', valign:'middle' });
      if (subtitle) slide.addText(subtitle, { x:0.45, y:0.1, w:10, h:0.72, fontSize:11, color:'B0C4DE', fontFace:'Arial', valign:'bottom' });
      // Slide label top-right
      slide.addText(`${projectName}  ·  ${reportDate}`, { x:10, y:0.12, w:3.1, h:0.66, fontSize:9, color:MUTED, align:'right', fontFace:'Arial', valign:'middle' });
    };

    const addFooter = (slide, pageLabel, total) => {
      slide.addShape('rect', { x:0.22, y:7.22, w:13.11, h:0.03, fill:{color:ACCENT} });
      slide.addText(`Generated ${generatedAt}`, { x:0.4, y:7.26, w:7, h:0.22, fontSize:8, color:MUTED, fontFace:'Arial' });
      if (pageLabel) slide.addText(pageLabel, { x:7.3, y:7.26, w:3, h:0.22, fontSize:8, color:MUTED, align:'center', fontFace:'Arial' });
      if (total) slide.addText(`Page ${pageLabel} of ${total}`, { x:10.5, y:7.26, w:2.6, h:0.22, fontSize:8, color:MUTED, align:'right', fontFace:'Arial' });
    };

    // KPI card helper
    const addKpiCard = (slide, x, y, w, h, label, value, sub, statusColor, icon) => {
      slide.addShape('roundRect', { x, y, w, h, rectRadius:0.07, fill:{color:WHITE}, line:{color:'DCE3EA', width:0.8} });
      slide.addShape('rect',      { x, y, w:0.07, h, fill:{color:statusColor} });
      slide.addShape('rect',      { x, y, w, h:0.07, fill:{color:statusColor} });
      if (icon) slide.addText(icon, { x:x+w-0.55, y:y+0.1, w:0.45, h:0.45, fontSize:18, fontFace:'Arial', align:'center' });
      slide.addText(label.toUpperCase(), { x:x+0.18, y:y+0.12, w:w-0.25, h:0.27, fontSize:9, bold:true, color:SLATE, fontFace:'Arial' });
      slide.addText(value, { x:x+0.18, y:y+0.38, w:w-0.25, h:0.7, fontSize:28, bold:true, color:statusColor, fontFace:'Arial', valign:'middle' });
      slide.addText(sub, { x:x+0.18, y:y+h-0.32, w:w-0.25, h:0.25, fontSize:9.5, color:SLATE, fontFace:'Arial' });
    };

    // ── SLIDE 1: Title / Cover ──────────────────────────────────────────
    let slide = pptx.addSlide();
    // Full bleed background gradient effect using two overlapping shapes
    slide.addShape('rect', { x:0, y:0, w:13.33, h:7.5, fill:{color:NAVY} });
    slide.addShape('rect', { x:0, y:0, w:6.5,   h:7.5, fill:{color:NAVY2} });
    // Decorative accent circles
    slide.addShape('ellipse', { x:9.5, y:-1.5, w:5, h:5, fill:{color:ACCENT}, line:{color:ACCENT,width:0}, transparency:75 });
    slide.addShape('ellipse', { x:10.5, y:3.5, w:4, h:4, fill:{color:TEAL}, line:{color:TEAL,width:0}, transparency:80 });
    // Left accent bar
    slide.addShape('rect', { x:0, y:0, w:0.35, h:7.5, fill:{color:ACCENT} });
    // Brand line
    slide.addShape('rect', { x:0.35, y:3.5, w:5.5, h:0.04, fill:{color:ACCENT} });
    // Titles
    slide.addText(projectName, { x:0.6, y:1.2, w:7, h:0.7, fontSize:36, bold:true, color:'B0C4DE', fontFace:'Arial' });
    slide.addText('Executive Summary', { x:0.6, y:1.85, w:10, h:1.1, fontSize:48, bold:true, color:WHITE, fontFace:'Arial' });
    slide.addText('Weekly Progress Report', { x:0.6, y:2.95, w:8, h:0.55, fontSize:19, color:'93C5FD', fontFace:'Arial' });
    slide.addText(reportDate, { x:0.6, y:4.1, w:5, h:0.45, fontSize:15, color:MUTED, fontFace:'Arial' });
    // Stats summary box
    slide.addShape('roundRect', { x:7.8, y:1.8, w:5.0, h:4.0, rectRadius:0.12, fill:{color:'FFFFFF'}, line:{color:'DCE3EA',width:0}, transparency:10 });
    slide.addText('AT A GLANCE', { x:8.1, y:2.05, w:4.4, h:0.35, fontSize:11, bold:true, color:ACCENT, fontFace:'Arial' });
    const quickStats = [
      { lbl:'Team Members',   val:`${S.total}` },
      { lbl:'Total Tasks',    val:`${S.gTotal}` },
      { lbl:'Completed',      val:`${S.gDone}` },
      { lbl:'Completion',     val:`${S.completion}%` },
      { lbl:'Overdue Tasks',  val:`${S.gOv}` },
    ];
    quickStats.forEach((qs,i) => {
      slide.addText(qs.lbl, { x:8.1, y:2.5+i*0.54, w:2.5, h:0.4, fontSize:11, color:MUTED, fontFace:'Arial', valign:'middle' });
      slide.addText(qs.val, { x:10.6, y:2.5+i*0.54, w:2, h:0.4, fontSize:14, bold:true, color:DARKGRAY, fontFace:'Arial', align:'right', valign:'middle' });
      if (i<quickStats.length-1) slide.addShape('rect', { x:8.1, y:2.88+i*0.54, w:4.5, h:0.01, fill:{color:'E2E8F0'} });
    });
    slide.addText(`Generated ${generatedAt}`, { x:0.6, y:6.9, w:9, h:0.28, fontSize:9, color:MUTED, fontFace:'Arial' });

    // ── SLIDE 2: RAG Status Overview ────────────────────────────────────
    slide = pptx.addSlide();
    addHeader(slide, 'Project Health Overview', 'RAG classification of all team members', GREEN);
    const ragTotal = S.total || 1;
    // Horizontal stacked bar
    let barX = 0.5, barY = 1.15, barW = 12.3, barH = 0.65;
    const segs = [
      {n:S.rag.green.length, color:GREEN, label:'On Track'},
      {n:S.rag.amber.length, color:AMBER, label:'Needs Attention'},
      {n:S.rag.red.length,   color:RED,   label:'At Risk'},
    ];
    segs.forEach(sg => {
      if (sg.n <= 0) return;
      const w = barW*(sg.n/ragTotal);
      slide.addShape('rect', { x:barX, y:barY, w, h:barH, fill:{color:sg.color} });
      if (w > 1.0) slide.addText(`${sg.n}`, { x:barX, y:barY, w, h:barH, fontSize:20, bold:true, color:WHITE, align:'center', valign:'middle', fontFace:'Arial' });
      barX += w;
    });
    // Legend
    slide.addText([
      {text:'● On Track ', options:{color:GREEN,bold:true}}, {text:`${S.rag.green.length} members  `, options:{color:SLATE}},
      {text:'● Needs Attention ', options:{color:AMBER,bold:true}}, {text:`${S.rag.amber.length} members  `, options:{color:SLATE}},
      {text:'● At Risk ', options:{color:RED,bold:true}}, {text:`${S.rag.red.length} members`, options:{color:SLATE}},
    ], { x:0.5, y:1.88, w:12.3, h:0.3, fontSize:11, fontFace:'Arial' });

    // 3 RAG category cards
    const ragCards = [
      {title:'✅  On Track', color:GREEN,  members:S.rag.green, desc:'≥80% complete, ≤1 overdue'},
      {title:'⚠️  Watch',    color:AMBER,  members:S.rag.amber, desc:'50–79% or low pace'},
      {title:'🔴  At Risk',  color:RED,    members:S.rag.red,   desc:'<50% complete or 4+ overdue'},
    ];
    ragCards.forEach((card, ci) => {
      const cx = 0.5 + ci*4.28, cy = 2.3, cw = 4.1, ch = 4.6;
      slide.addShape('roundRect', { x:cx, y:cy, w:cw, h:ch, rectRadius:0.09, fill:{color:LIGHT}, line:{color:'DCE3EA',width:0.7} });
      slide.addShape('rect', { x:cx, y:cy, w:cw, h:0.52, fill:{color:card.color}, rectRadius:0.09 });
      slide.addText(card.title, { x:cx+0.15, y:cy+0.06, w:cw-0.2, h:0.4, fontSize:13, bold:true, color:WHITE, fontFace:'Arial' });
      slide.addText(card.desc, { x:cx+0.15, y:cy+0.56, w:cw-0.2, h:0.25, fontSize:9, color:SLATE, fontFace:'Arial' });
      slide.addText(`${card.members.length}`, { x:cx+cw-1.0, y:cy+0.48, w:0.85, h:0.45, fontSize:24, bold:true, color:card.color, fontFace:'Arial', align:'right' });
      const names = card.members.slice(0,10).map(m=>`${m.owner}  (${m.this_week}%)`).join('\n');
      if (names) slide.addText(names, { x:cx+0.15, y:cy+0.9, w:cw-0.25, h:3.6, fontSize:10.5, color:DARKGRAY, fontFace:'Arial', valign:'top', paraSpaceAfter:2 });
      if (card.members.length > 10) slide.addText(`+${card.members.length-10} more…`, { x:cx+0.15, y:cy+ch-0.35, w:cw-0.25, h:0.28, fontSize:9, color:MUTED, fontFace:'Arial' });
    });
    addFooter(slide, '2');

    // ── SLIDE 3: Key Metrics ─────────────────────────────────────────────
    slide = pptx.addSlide();
    addHeader(slide, 'Key Performance Metrics', 'Snapshot of this reporting period', TEAL);
    const kpis = [
      { label:'Overall Completion', value:`${S.completion}%`, sub:`${S.gDone} of ${S.gTotal} tasks done`,
        icon:'📊', good:S.completion>=80, warn:S.completion>=50 },
      { label:'Overdue Rate', value:`${S.overdueRate}%`, sub:`${S.gOv} tasks past due`,
        icon:'⏰', good:S.overdueRate<=5, warn:S.overdueRate<=15 },
      { label:'WIP Ratio', value:`${S.wipRatio}%`, sub:`${S.gIP} tasks in progress`,
        icon:'⚙️', good:S.wipRatio<=25, warn:S.wipRatio<=40 },
      { label:'Approval Queue', value:`${S.gWFA}`, sub:'waiting for sign-off',
        icon:'✍️', good:S.gWFA<=3, warn:S.gWFA<=8 },
      { label:'Team Members', value:`${S.total}`, sub:'active contributors',
        icon:'👥', good:true },
      { label:'Green Members', value:`${S.rag.green.length}`, sub:`${Math.round(S.rag.green.length/ragTotal*100)}% of team on track`,
        icon:'✅', good:S.rag.green.length/ragTotal>=0.6, warn:S.rag.green.length/ragTotal>=0.4 },
    ];
    const kW = 4.0, kH = 1.55, kGap = 0.16, kX0 = 0.5, kY0 = 1.1;
    kpis.forEach((k,i) => {
      const col = i%3, row = Math.floor(i/3);
      const kx = kX0 + col*(kW+kGap);
      const ky = kY0 + row*(kH+kGap);
      const col_ = k.good ? GREEN : k.warn ? AMBER : RED;
      addKpiCard(slide, kx, ky, kW, kH, k.label, k.value, k.sub, col_, k.icon);
    });
    addFooter(slide, '3');

    // ── SLIDE 4: Escalation Watchlist ────────────────────────────────────
    slide = pptx.addSlide();
    addHeader(slide, 'Escalation Watchlist', 'All members requiring PM attention — sorted by risk score', ORANGE);
    if (S.watchlist.length) {
      // Split into pages if too many rows; show max 10 here
      const show = S.watchlist.slice(0,10);
      const tblRows = [[
        {text:'#',          options:{bold:true,color:WHITE,fill:{color:ORANGE},align:'center',fontSize:11}},
        {text:'Owner',      options:{bold:true,color:WHITE,fill:{color:ORANGE},fontSize:11}},
        {text:'% Done',     options:{bold:true,color:WHITE,fill:{color:ORANGE},align:'center',fontSize:11}},
        {text:'Overdue',    options:{bold:true,color:WHITE,fill:{color:ORANGE},align:'center',fontSize:11}},
        {text:'WoW Δ',      options:{bold:true,color:WHITE,fill:{color:ORANGE},align:'center',fontSize:11}},
        {text:'Flags',      options:{bold:true,color:WHITE,fill:{color:ORANGE},fontSize:11}},
      ]];
      show.forEach((r,i) => {
        const bg = i%2 ? LIGHT : WHITE;
        const dStr = r.delta===null||r.delta===undefined?'N/A':(r.delta>=0?'+':'')+r.delta+'%';
        const dCol = r.delta>0?GREEN:r.delta<0?RED:SLATE;
        tblRows.push([
          {text:String(i+1),             options:{align:'center', fill:{color:bg}, fontSize:11}},
          {text:r.owner,                  options:{bold:true, fill:{color:bg}, fontSize:11, color:DARKGRAY}},
          {text:`${r.this_week}%`,        options:{align:'center', fill:{color:bg}, fontSize:11}},
          {text:`${r.overdue||0}`,        options:{align:'center', fill:{color:bg}, fontSize:11, color:r.overdue>=4?RED:r.overdue>=1?ORANGE:SLATE, bold:r.overdue>0}},
          {text:dStr,                     options:{align:'center', fill:{color:bg}, fontSize:11, color:dCol}},
          {text:r._reasons.join(' · '),   options:{fill:{color:bg}, fontSize:10, color:SLATE}},
        ]);
      });
      slide.addTable(tblRows, { x:0.4, y:1.05, w:12.5, colW:[0.6,2.5,1.2,1.1,1.1,6.0],
        fontSize:11, fontFace:'Arial', border:{type:'solid',color:'DCE3EA',pt:0.4}, rowH:0.42, autoPage:false });
      if (S.watchlist.length > 10) {
        slide.addText(`+ ${S.watchlist.length-10} additional members with concerns — see full dashboard for details.`,
          { x:0.4, y:7.0, w:12.5, h:0.22, fontSize:9, color:MUTED, fontFace:'Arial', italic:true });
      }
    } else {
      slide.addShape('roundRect', { x:1.5, y:2.0, w:10.3, h:2.5, rectRadius:0.12, fill:{color:'F0FDF4'}, line:{color:'BBF7D0',width:1} });
      slide.addText('🎉', { x:1.5, y:2.2, w:10.3, h:1.0, fontSize:48, align:'center', fontFace:'Arial' });
      slide.addText('No escalations this week!', { x:1.5, y:3.1, w:10.3, h:0.6, fontSize:22, bold:true, color:GREEN, align:'center', fontFace:'Arial' });
      slide.addText('All team members are operating within acceptable thresholds.', { x:1.5, y:3.65, w:10.3, h:0.4, fontSize:13, color:SLATE, align:'center', fontFace:'Arial' });
    }
    addFooter(slide, '4');

    // ── SLIDE 5: Team Performance Breakdown ──────────────────────────────
    slide = pptx.addSlide();
    addHeader(slide, 'Team Performance Breakdown', 'Individual completion rates — all members', PURPLE);
    const maxPerSlide = 12;
    const teamShow = S.teamRows.slice(0, maxPerSlide);
    if (teamShow.length) {
      const tRows = [[
        {text:'Member',      options:{bold:true,color:WHITE,fill:{color:PURPLE},fontSize:10}},
        {text:'Done',        options:{bold:true,color:WHITE,fill:{color:PURPLE},align:'center',fontSize:10}},
        {text:'Total',       options:{bold:true,color:WHITE,fill:{color:PURPLE},align:'center',fontSize:10}},
        {text:'% Done',      options:{bold:true,color:WHITE,fill:{color:PURPLE},align:'center',fontSize:10}},
        {text:'Overdue',     options:{bold:true,color:WHITE,fill:{color:PURPLE},align:'center',fontSize:10}},
        {text:'WoW Δ',       options:{bold:true,color:WHITE,fill:{color:PURPLE},align:'center',fontSize:10}},
        {text:'Status',      options:{bold:true,color:WHITE,fill:{color:PURPLE},align:'center',fontSize:10}},
      ]];
      teamShow.forEach((r,i) => {
        const bg = i%2 ? LIGHT : WHITE;
        const pct = r.this_week||0, ov = r.overdue||0;
        const status = pct>=80&&ov<=1?'✅ On Track':pct<50||ov>=4?'🔴 At Risk':'⚠️ Watch';
        const stCol  = pct>=80&&ov<=1?GREEN:pct<50||ov>=4?RED:AMBER;
        const dStr = r.delta===null||r.delta===undefined?'—':(r.delta>=0?'+':'')+r.delta+'%';
        tRows.push([
          {text:r.owner,                         options:{bold:true,fill:{color:bg},fontSize:10,color:DARKGRAY}},
          {text:String(r.completed||0),          options:{align:'center',fill:{color:bg},fontSize:10}},
          {text:String(r.total||0),              options:{align:'center',fill:{color:bg},fontSize:10}},
          {text:`${pct}%`,                       options:{align:'center',fill:{color:bg},fontSize:10,bold:true,color:pct>=80?GREEN:pct<50?RED:AMBER}},
          {text:String(ov),                      options:{align:'center',fill:{color:bg},fontSize:10,color:ov>=4?RED:ov>=1?ORANGE:SLATE,bold:ov>0}},
          {text:dStr,                            options:{align:'center',fill:{color:bg},fontSize:10,color:r.delta>0?GREEN:r.delta<0?RED:SLATE}},
          {text:status,                          options:{align:'center',fill:{color:bg},fontSize:10,color:stCol,bold:true}},
        ]);
      });
      slide.addTable(tRows, { x:0.35, y:1.05, w:12.6, colW:[2.5,0.9,0.9,1.1,1.1,1.1,5.0],
        fontSize:10, fontFace:'Arial', border:{type:'solid',color:'DCE3EA',pt:0.4}, rowH:0.39, autoPage:false });
      if (S.teamRows.length > maxPerSlide) {
        slide.addText(`Showing ${maxPerSlide} of ${S.teamRows.length} members. See full dashboard for complete view.`,
          { x:0.35, y:7.0, w:12.6, h:0.22, fontSize:9, color:MUTED, italic:true, fontFace:'Arial' });
      }
    }
    addFooter(slide, '5');

    // ── SLIDE 6: Key Risks ───────────────────────────────────────────────
    if (risks.length) {
      slide = pptx.addSlide();
      addHeader(slide, 'Key Risks & Issues', 'AI-identified risks requiring attention this week', AMBER);
      const riskColors = [RED, ORANGE, AMBER, TEAL, PURPLE, NAVY2];
      let ry = 1.08;
      risks.forEach((r, ri) => {
        const rh = r.tip ? 1.18 : 0.95;
        slide.addShape('roundRect', { x:0.45, y:ry, w:12.4, h:rh, rectRadius:0.07, fill:{color:LIGHT}, line:{color:'E2E8F0',width:0.6} });
        slide.addShape('rect', { x:0.45, y:ry, w:0.09, h:rh, fill:{color:riskColors[ri%riskColors.length]} });
        slide.addText(`Risk ${ri+1}`, { x:0.62, y:ry+0.06, w:1.2, h:0.26, fontSize:9, bold:true, color:riskColors[ri%riskColors.length], fontFace:'Arial' });
        slide.addText(r.name||'', { x:1.7, y:ry+0.06, w:11.0, h:0.3, fontSize:13, bold:true, color:DARKGRAY, fontFace:'Arial' });
        if (r.note) slide.addText(r.note, { x:0.62, y:ry+0.38, w:12.1, h:0.3, fontSize:11, color:SLATE, fontFace:'Arial' });
        if (r.tip)  slide.addText(`💡 Mitigation: ${r.tip}`, { x:0.62, y:ry+0.7, w:12.1, h:0.3, fontSize:10.5, italic:true, color:'92640C', fontFace:'Arial' });
        ry += rh + 0.1;
      });
      addFooter(slide, '6');
    }

    // ── SLIDE 7: Wins & Highlights ───────────────────────────────────────
    slide = pptx.addSlide();
    addHeader(slide, "This Week's Wins", 'Top performers and positive momentum', GREEN);
    if (S.wins.length) {
      const wRows = [[
        {text:'Member',        options:{bold:true,color:WHITE,fill:{color:GREEN},fontSize:11}},
        {text:'Completion',    options:{bold:true,color:WHITE,fill:{color:GREEN},align:'center',fontSize:11}},
        {text:'Tasks Done',    options:{bold:true,color:WHITE,fill:{color:GREEN},align:'center',fontSize:11}},
        {text:'WoW Change',    options:{bold:true,color:WHITE,fill:{color:GREEN},align:'center',fontSize:11}},
        {text:'Highlight',     options:{bold:true,color:WHITE,fill:{color:GREEN},fontSize:11}},
      ]];
      S.wins.forEach((r,i) => {
        const bg = i%2 ? LIGHT : WHITE;
        const d = r.delta;
        const dStr = d===null||d===undefined?'NEW':(d>=0?'+':'')+d+'%';
        const highlight = r.this_week>=100?'✅ Fully complete!':r.this_week>=90?'Outstanding progress':r.this_week>=80?'On track & strong':'Great weekly jump';
        wRows.push([
          {text:r.owner,                            options:{bold:true,fill:{color:bg},fontSize:11,color:DARKGRAY}},
          {text:`${r.this_week}%`,                  options:{align:'center',fill:{color:bg},fontSize:14,bold:true,color:GREEN}},
          {text:`${r.completed||0}/${r.total||0}`,  options:{align:'center',fill:{color:bg},fontSize:11}},
          {text:dStr,                               options:{align:'center',fill:{color:bg},fontSize:11,bold:true,color:d>=0?GREEN:RED}},
          {text:highlight,                          options:{fill:{color:bg},fontSize:10.5,color:SLATE,italic:true}},
        ]);
      });
      slide.addTable(wRows, { x:0.4, y:1.1, w:12.5, colW:[2.5,1.6,1.5,1.6,5.3],
        fontSize:11, fontFace:'Arial', border:{type:'solid',color:'DCE3EA',pt:0.4}, rowH:0.48, autoPage:false });
    } else {
      slide.addText('No standout performers this week — but the team is making steady progress.', { x:0.5, y:2.5, w:12.3, h:0.5, fontSize:15, color:SLATE, fontFace:'Arial' });
    }
    // AI summary panel
    if (summaryText) {
      const tY = S.wins.length ? 1.1 + (S.wins.length+1)*0.48 + 0.3 : 1.3;
      slide.addText('📝 AI-Generated Weekly Commentary', { x:0.4, y:tY, w:12.5, h:0.35, fontSize:12, bold:true, color:NAVY, fontFace:'Arial' });
      const boxH = Math.max(0.8, 7.1 - tY - 0.45);
      slide.addShape('roundRect', { x:0.4, y:tY+0.38, w:12.5, h:boxH, rectRadius:0.08, fill:{color:LIGHT}, line:{color:'DCE3EA',width:0.7} });
      slide.addText(summaryText, { x:0.6, y:tY+0.5, w:12.1, h:boxH-0.22, fontSize:11.5, color:DARKGRAY, valign:'top', fontFace:'Arial' });
    }
    addFooter(slide, '7');

    // ── SLIDE 8: Closing / Actions ───────────────────────────────────────
    slide = pptx.addSlide();
    slide.addShape('rect', { x:0, y:0, w:13.33, h:7.5, fill:{color:NAVY} });
    slide.addShape('rect', { x:0, y:0, w:0.35, h:7.5, fill:{color:ACCENT} });
    slide.addShape('ellipse', { x:9.5, y:-1.5, w:5, h:5, fill:{color:ACCENT}, line:{color:ACCENT,width:0}, transparency:80 });
    slide.addShape('ellipse', { x:10.5, y:3.5, w:4, h:4, fill:{color:TEAL}, line:{color:TEAL,width:0}, transparency:85 });

    slide.addText('Recommended Actions', { x:0.6, y:1.0, w:10, h:0.7, fontSize:34, bold:true, color:WHITE, fontFace:'Arial' });
    slide.addShape('rect', { x:0.6, y:1.72, w:4.5, h:0.04, fill:{color:ACCENT} });

    const actions = [
      S.watchlist.length > 0 ? `Follow up with ${S.watchlist.slice(0,3).map(w=>w.owner).join(', ')} on overdue items` : 'No immediate escalations required',
      S.gWFA > 0 ? `Clear ${S.gWFA} approval queue item${S.gWFA>1?'s':''} to unblock progress` : 'Approval queue is clear ✓',
      S.overdueRate > 10 ? `Address high overdue rate (${S.overdueRate}%) — review task distribution` : `Maintain low overdue rate (${S.overdueRate}%) with current approach`,
      S.rag.red.length > 0 ? `${S.rag.red.length} member${S.rag.red.length>1?'s':''} at risk — schedule 1:1 check-ins` : 'All at-risk members have been addressed ✓',
      risks.length > 0 ? `Monitor ${risks.length} identified risk${risks.length>1?'s':''} — see risk slide for mitigations` : 'No major risks flagged this week',
    ];
    actions.forEach((action, i) => {
      slide.addShape('ellipse', { x:0.6, y:2.05+i*0.75, w:0.3, h:0.3, fill:{color:ACCENT} });
      slide.addText(String(i+1), { x:0.6, y:2.05+i*0.75, w:0.3, h:0.3, fontSize:11, bold:true, color:WHITE, align:'center', valign:'middle', fontFace:'Arial' });
      slide.addText(action, { x:1.05, y:2.0+i*0.75, w:10.5, h:0.4, fontSize:13, color:'CBD5E1', fontFace:'Arial', valign:'middle' });
    });

    slide.addText(`${projectName}  ·  ${reportDate}  ·  ${generatedAt}`, { x:0.6, y:6.9, w:11, h:0.25, fontSize:9, color:MUTED, fontFace:'Arial' });

    await pptx.writeFile({ fileName: `executive-summary-${reportDate || 'report'}.pptx` });
    toast('✓ Executive Summary downloaded.');
  } catch (e) {
    console.error('[export-executive-pptx]', e);
    toast('Export failed: '+e.message);
  }
}

// ── export Epic daily status report (one column per day, side by side) ────
// Pulls every task + subtask under one epic straight from Jira (via the
// Worker's read-only `epic_issues` action, which also returns each issue's
// changelog) and writes a coloured .xlsx for management, with every day from
// a chosen start date through today laid out as its own column — so a
// stalled task (same status repeated day after day) is visible at a glance
// across the row, next to who owns it.
// Every day's status is CHECKED, not saved: we ask Jira's own status-change
// history what the status was at the end of each day, so nothing needs to
// be written back to the repo. Today's column is always the *live* status
// at the moment of download — export it once or ten times a day, it's
// always current. The start date is picked in the "Export Epic Excel" modal
// (openEpicExcelModal / confirmEpicExcelExport below); EPIC_HISTORY_START is
// just the fallback default shown the first time, before anyone has picked
// their own date (which is then remembered in localStorage).
const EPIC_KEY = 'FIBTMP-489';
const EPIC_HISTORY_START = '2026-07-13'; // yyyy-mm-dd, default start shown in the modal

async function fetchEpicIssues(){
  if (!GH_PROXY) throw new Error('No Worker proxy configured (meta gh-proxy).');
  const pw = sessionStorage.getItem('pw_cache') || '';
  const r = await window.fetch(GH_PROXY, {
    method:'POST',
    headers:{'Content-Type':'application/json','X-Proxy-Auth':pw},
    body: JSON.stringify({action:'epic_issues', epicKey: EPIC_KEY})
  });
  if (!r.ok){
    let msg = 'HTTP '+r.status;
    try { const j = await r.json(); if (j.message) msg = j.message + (j.detail?(' — '+j.detail):''); } catch(e){}
    throw new Error(msg);
  }
  const j = await r.json();
  return j.issues || [];
}

// Walks an issue's changelog for "status" field changes and returns the
// status that was in effect at cutoffMs. Returns null if the issue didn't
// exist yet at that time.
function _statusAsOf(issue, cutoffMs){
  const f = issue.fields||{};
  const created = f.created ? new Date(f.created).getTime() : null;
  if (created && created > cutoffMs) return null; // wasn't created yet
  const histories = ((issue.changelog||{}).histories) || [];
  const events = [];
  for (const h of histories){
    const when = h.created ? new Date(h.created).getTime() : null;
    if (when === null || isNaN(when)) continue;
    for (const it of (h.items||[])){
      if ((it.field||'').toLowerCase() === 'status'){
        events.push({when, from: it.fromString||'', to: it.toString||''});
      }
    }
  }
  events.sort((a,b)=>a.when-b.when);
  let status = null;
  for (const e of events){
    if (e.when <= cutoffMs) status = e.to;
    else break;
  }
  if (status === null){
    // No status change on/before cutoff — either it never changed at all
    // (use the pre-first-change value if we have one, else today's status),
    // or every change happened after cutoff (use the very first "from").
    status = events.length ? events[0].from : (((f.status)||{}).name || 'Unknown');
  }
  return status;
}

// Status → fill colour, reused for both status cells.
function _epicStatusFill(status){
  const s = (status||'').toLowerCase();
  if (s.includes('done') || s.includes('closed') || s.includes('resolved') || s === 'available') return 'C6EFCE';
  if (s.includes('progress')) return 'BDD7EE';
  if (s.includes('block'))    return 'F4B7B7';
  if (s.includes('wait') || s.includes('approv') || s.includes('review')) return 'FFE699';
  return 'E7E6E6';
}

// Issue type → fill colour, same soft palette family as the status cells so
// the whole sheet reads as one consistent colour system.
function _epicTypeFill(type){
  const t = (type||'').toLowerCase();
  if (t.includes('epic'))    return 'D9C2EE'; // purple
  if (t.includes('story'))   return 'C6EFCE'; // green
  if (t.includes('bug'))     return 'F4B7B7'; // red
  if (t.includes('sub'))     return 'FFE699'; // amber
  if (t.includes('task'))    return 'BDD7EE'; // blue
  return 'E7E6E6'; // grey fallback
}

// Builds the list of local-midnight Date objects from startStr (yyyy-mm-dd,
// falls back to EPIC_HISTORY_START) through today (inclusive). Today is
// always the last entry. If startStr is after today, just today is used.
function _epicDayList(startStr){
  const [sy,sm,sd] = (startStr || EPIC_HISTORY_START).split('-').map(Number);
  const start = new Date(sy, (sm||1)-1, sd||1);
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const days = [];
  for (let d = new Date(start); d <= today; d.setDate(d.getDate()+1)){
    days.push(new Date(d));
  }
  if (!days.length) days.push(today); // guard: start date in the future
  return days;
}

// Per-day status for one issue across the whole day list. Every day except
// the last (today) is looked up from the changelog as of the *end* of that
// day (i.e. just before the next day starts). Today is always the issue's
// live current status. null = issue didn't exist yet on that day.
function _dailyStatuses(issue, days){
  const out = [];
  for (let i=0;i<days.length;i++){
    if (i === days.length-1){
      out.push(((issue.fields.status||{}).name) || 'Unknown');
    } else {
      out.push(_statusAsOf(issue, days[i+1].getTime()));
    }
  }
  return out;
}

// How many days in a row (counting back from today) the status hasn't
// moved — the number a manager actually cares about: a high count next to
// an owner's name means that task has been sitting untouched.
function _idleStreak(daily){
  const last = daily[daily.length-1];
  let streak = 0;
  for (let i=daily.length-1;i>=0;i--){
    if (daily[i] === last) streak++; else break;
  }
  return streak;
}

// Idle-streak → fill colour: green while fresh, amber once it's worth a
// look, red once it's clearly stalled.
function _idleFill(days){
  if (days >= 5) return 'F4B7B7';
  if (days >= 3) return 'FFE699';
  return 'C6EFCE';
}

// A long idle streak only means "stalled, go check on it" for tasks that
// are still open. If the task is Done/Closed/Resolved, that same streak is
// actually good news — it's just been sitting finished — so it should read
// as "Completed", not get flagged red like a stuck task.
function _isDoneStatus(status){
  const s = (status||'').toLowerCase();
  return s.includes('done') || s.includes('closed') || s.includes('resolved') || s === 'available';
}

// Opens the "choose start date" modal. Defaults to whatever was picked last
// time (remembered in localStorage), or EPIC_HISTORY_START the first time.
function openEpicExcelModal(){
  const inp = document.getElementById('epic-excel-start');
  const now = new Date();
  const todayStr = now.toISOString().slice(0,10);
  let saved = null;
  try { saved = localStorage.getItem('epicExcelStart'); } catch(e){}
  inp.value = (saved && saved <= todayStr) ? saved : EPIC_HISTORY_START;
  inp.max = todayStr;
  const lbl = document.getElementById('epic-excel-today-label');
  if (lbl) lbl.textContent = now.toLocaleDateString('en-GB', {day:'2-digit', month:'short', year:'numeric'}) + ' (today)';
  openModal('epic-excel-modal');
}

// Reads the chosen date out of the modal, remembers it for next time, and
// kicks off the actual export.
function confirmEpicExcelExport(){
  const inp = document.getElementById('epic-excel-start');
  const val = inp && inp.value;
  if (!val){ toast('Pick a start date first.'); return; }
  try { localStorage.setItem('epicExcelStart', val); } catch(e){}
  closeModal('epic-excel-modal');
  exportEpicExcel(val);
}

async function exportEpicExcel(historyStart){
  if (!GH_PROXY){ toast('This export needs the live Worker connection (meta gh-proxy).'); return; }
  toast(`Pulling ${EPIC_KEY} from Jira…`);
  try {
    const issues = await fetchEpicIssues();
    if (!issues.length){ toast(`No tasks/subtasks found under ${EPIC_KEY}.`); return; }

    const startLabel = historyStart || EPIC_HISTORY_START;
    const days = _epicDayList(startLabel); // startLabel … today, today last
    const now = new Date();
    const dateLabel = now.toISOString().slice(0,10);

    // Owner-lookup map (kept for future use; each row now just shows its own assignee).
    const ownerByKey = {};
    issues.forEach(i => { ownerByKey[i.key] = (i.fields.assignee && i.fields.assignee.displayName) || 'Unassigned'; });

    const base = (REPORT.jira_base_url || 'https://fibtask.atlassian.net').replace(/\/+$/,'');

    const rows = issues.map(issue=>{
      const f = issue.fields||{};
      const key = issue.key;
      const owner = ownerByKey[key];
      const summary = (f.summary||'').slice(0,200);
      const type = ((f.issuetype||{}).name)||'';
      const daily = _dailyStatuses(issue, days); // one entry per day, null = not created yet
      const idle = _idleStreak(daily);
      const lastStatus = daily[daily.length-1];
      const link = `${base}/browse/${encodeURIComponent(key)}`;
      return { key, owner, summary, type, daily, idle, lastStatus, link };
    });

    const s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/npm/xlsx-js-style/dist/xlsx.bundle.js';
    s.onload = () => {
      try {
        // Columns: Key/Summary/Owner/Type, then one status column per day
        // (side by side, so a frozen status jumps out across the row),
        // then Idle Days (how long the status has sat unchanged), then Link.
        const dayLabels = days.map((d,i)=>{
          const label = d.toLocaleDateString('en-GB', {day:'2-digit', month:'short'});
          return i === days.length-1 ? `${label} (Today)` : label;
        });
        const header = ['Key','Summary','Owner','Type', ...dayLabels, 'Idle / Completed','Link'];
        const idleCol = 4 + days.length;
        const linkCol = idleCol + 1;
        const lastColLetter = XLSX.utils.encode_col(linkCol);

        // Row 0 is a plain title/generated-on banner (merged across every
        // column); row 1 is the real header; data starts at row 2. This is
        // the "when was this pulled" note — today's column always says
        // "(Today)" too, but this spells out the exact generation time so
        // it's obvious the file is fresh even printed out or forwarded.
        const generatedAt = now.toLocaleString('en-GB', {day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'});
        const titleText = `Epic ${EPIC_KEY}  ·  ${startLabel} → ${dateLabel} (Today)  ·  Generated ${generatedAt}`;
        const HEADER_ROW = 1, DATA_START = 2;

        const headStyle = { font:{bold:true,color:{rgb:'FFFFFF'},sz:12}, fill:{fgColor:{rgb:'1F4E78'}}, alignment:{horizontal:'center',vertical:'center',wrapText:true}, border:{bottom:{style:'thin',color:{rgb:'0F2D46'}}} };
        const titleStyle = { font:{bold:true,color:{rgb:'1F4E78'},sz:11}, alignment:{horizontal:'left',vertical:'center'} };
        const aoa = [
          [titleText],
          header,
          ...rows.map(r=>[
            r.key, r.summary, r.owner, r.type,
            ...r.daily.map(st => st===null ? '—' : st),
            _isDoneStatus(r.lastStatus) ? `Completed (${r.idle}d)` : r.idle,
            r.link
          ])
        ];
        const ws = XLSX.utils.aoa_to_sheet(aoa);
        // Day columns are wider now and wrap, so a long status (e.g.
        // "Revision Level 1") stays inside its own cell on 1-2 lines
        // instead of overflowing across the neighbouring day columns.
        ws['!cols'] = [{wch:12},{wch:60},{wch:20},{wch:12}, ...days.map(()=>({wch:16})), {wch:16},{wch:38}];
        ws['!rows'] = [{hpx:20}, {hpx:34}, ...rows.map(()=>({hpx:32}))];
        ws['!merges'] = [{ s:{r:0,c:0}, e:{r:0,c:linkCol} }];
        ws['!freeze'] = {xSplit:4, ySplit:DATA_START}; // Key/Summary/Owner/Type stay put; title+header stay put too
        ws['!autofilter'] = {ref:`A${HEADER_ROW+1}:${lastColLetter}${rows.length+DATA_START}`};
        const titleAddr = XLSX.utils.encode_cell({r:0,c:0});
        if (ws[titleAddr]) ws[titleAddr].s = titleStyle;
        for (let c=0;c<header.length;c++){
          const addr = XLSX.utils.encode_cell({r:HEADER_ROW,c});
          if (ws[addr]) ws[addr].s = headStyle;
        }
        const plainCols = [0,1,2]; // Key, Summary, Owner — banded, no special colour
        rows.forEach((r,i)=>{
          const rr = i+DATA_START;
          const bandFill = i%2===0 ? 'FFFFFF' : 'F2F6FA';
          const border = {bottom:{style:'thin',color:{rgb:'DCE3EA'}}};
          plainCols.forEach(c=>{
            const addr = XLSX.utils.encode_cell({r:rr,c});
            if (ws[addr]) ws[addr].s = { fill:{fgColor:{rgb:bandFill}}, alignment:{vertical:'center', wrapText:c===1}, border };
          });
          const typeAddr = XLSX.utils.encode_cell({r:rr,c:3});
          if (ws[typeAddr]) ws[typeAddr].s = { fill:{fgColor:{rgb:_epicTypeFill(r.type)}}, alignment:{horizontal:'center',vertical:'center',wrapText:true}, border };
          r.daily.forEach((st,di)=>{
            const c = 4+di;
            const addr = XLSX.utils.encode_cell({r:rr,c});
            if (!ws[addr]) return;
            if (st === null){
              ws[addr].s = { font:{sz:10,color:{rgb:'AAAAAA'},italic:true}, fill:{fgColor:{rgb:'F2F2F2'}}, alignment:{horizontal:'center',vertical:'center',wrapText:true}, border };
            } else {
              ws[addr].s = { font:{sz:10}, fill:{fgColor:{rgb:_epicStatusFill(st)}}, alignment:{horizontal:'center',vertical:'center',wrapText:true}, border };
            }
          });
          const idleAddr = XLSX.utils.encode_cell({r:rr,c:idleCol});
          if (ws[idleAddr]) {
            if (_isDoneStatus(r.lastStatus)) {
              // Finished work sitting still isn't a problem — frame it as a
              // positive outcome, not a stalled-task warning.
              ws[idleAddr].s = { font:{bold:true,color:{rgb:'2E7D32'}}, fill:{fgColor:{rgb:'C6EFCE'}}, alignment:{horizontal:'center',vertical:'center'}, border };
            } else {
              ws[idleAddr].s = { font:{bold:r.idle>=3,color:{rgb:r.idle>=5?'C00000':'333333'}}, fill:{fgColor:{rgb:_idleFill(r.idle)}}, alignment:{horizontal:'center',vertical:'center'}, border };
            }
          }
          const linkAddr = XLSX.utils.encode_cell({r:rr,c:linkCol});
          if (ws[linkAddr]){
            ws[linkAddr].s = { font:{color:{rgb:'1155CC'},underline:true}, fill:{fgColor:{rgb:bandFill}}, alignment:{vertical:'center'}, border };
            ws[linkAddr].l = { Target: r.link, Tooltip: 'Open in Jira' };
          }
        });
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, EPIC_KEY);
        XLSX.writeFile(wb, `${EPIC_KEY}-daily-status-${startLabel}_to_${dateLabel}.xlsx`);
        toast('✓ Epic Excel downloaded.');
      } catch(e){
        console.error('[export-epic]', e);
        toast('Export failed: '+e.message);
      }
    };
    s.onerror = () => toast('Failed to load styled XLSX library.');
    document.head.appendChild(s);
  } catch(e){
    console.error('[export-epic]', e);
    toast('Export failed: '+e.message);
  }
}

// ── export image modal ─────────────────────────────────────────────────────
const hiddenPeople = new Set();

function openExportModal() {
  // populate history week selector
  const hist = REPORT.history||[];
  const sel = document.getElementById('exp-hist-week');
  sel.innerHTML = '';
  hist.slice().reverse().forEach((s,i)=>{
    const o=document.createElement('option');
    o.value=i; o.textContent=s.date+(i===0?' (latest)':'');
    sel.appendChild(o);
  });

  // populate people buttons
  // IMPORTANT: REPORT.rows only contains VISIBLE people (server-side filter).
  // Merge with hiddenPeople + history snapshots so we can un-hide them too.
  const btns = document.getElementById('exp-people-btns');
  btns.innerHTML = '';
  const allNames = new Set();
  REPORT.rows.forEach(r => allNames.add(r.owner));
  hiddenPeople.forEach(n => allNames.add(n));
  // Also include people from the most recent history snapshot in case
  // someone is hidden AND has left the project (still want to see/manage them)
  if (hist.length) {
    const recent = hist[hist.length-1];
    Object.keys(recent.people || {}).forEach(n => allNames.add(n));
  }
  const sortedNames = [...allNames].sort((a,b)=>a.toLowerCase().localeCompare(b.toLowerCase()));
  sortedNames.forEach(name => {
    const btn = document.createElement('button');
    const isHidden = hiddenPeople.has(name);
    btn.className = 'vis-btn' + (isHidden ? ' hidden-person' : '');
    btn.dataset.owner = name;
    btn.innerHTML = (isHidden ? '🙈' : '👁') + ' ' + esc(name);
    btn.onclick = () => togglePersonVisibility(name, btn);
    btns.appendChild(btn);
  });
  // Count display
  const countLabel = `${sortedNames.length} total · ${hiddenPeople.size} hidden`;
  const lbl = document.querySelector('#exp-people-btns');
  if (lbl && lbl.previousElementSibling) {
    lbl.previousElementSibling.querySelector('span').textContent = `(${countLabel} — click to toggle)`;
  }

  // sync check-item styling
  document.querySelectorAll('#exp-sections .check-item input').forEach(cb=>{
    cb.closest('.check-item').classList.toggle('on', cb.checked);
    cb.onchange = () => {
      cb.closest('.check-item').classList.toggle('on', cb.checked);
      if(cb.dataset.sec==='hist') {
        document.getElementById('exp-hist-sel-row').style.display = cb.checked?'':'none';
      }
    };
  });

  openModal('export-modal');
}

function togglePersonVisibility(owner, btn) {
  if (hiddenPeople.has(owner)) {
    hiddenPeople.delete(owner);
    btn.className = 'vis-btn';
    btn.innerHTML = '👁 ' + esc(owner);
  } else {
    hiddenPeople.add(owner);
    btn.className = 'vis-btn hidden-person';
    btn.innerHTML = '🙈 ' + esc(owner);
  }
  // Re-render tables live so the change is visible immediately behind the modal
  _rerenderTables();
}

// ── compare Excel modal ────────────────────────────────────────────────────
function openCompareModal() {
  document.getElementById('cmp-wrap').innerHTML = '';
  document.getElementById('cmp-file').value = '';
  openModal('compare-modal');
}

function loadCompareExcel(input) {
  const file = input.files[0];
  if (!file) return;
  const wrap = document.getElementById('cmp-wrap');
  wrap.innerHTML = '<p style="color:#64748b;font-size:12.5px;padding:12px 0">Parsing…</p>';
  const s=document.createElement('script');
  s.src='https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js';
  s.onload=()=>{
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const wb  = XLSX.read(e.target.result, {type:'array'});
        const ws  = wb.Sheets[wb.SheetNames[0]];
        const aoa = XLSX.utils.sheet_to_json(ws, {header:1});
        if (aoa.length < 2) { wrap.innerHTML='<p style="color:#dc2626;font-size:12.5px">No data found in Excel.</p>'; return; }

        // Try to find owner column (look for "owner" or "name" or "assignee" in headers)
        const hdr = (aoa[0]||[]).map(h=>String(h||'').toLowerCase());
        const ownerCol = hdr.findIndex(h=>h.includes('owner')||h.includes('name')||h.includes('assignee'));
        const pctCol   = hdr.findIndex(h=>h.includes('%')||h.includes('percent')||h.includes('completion'));

        if (ownerCol===-1) {
          wrap.innerHTML='<p style="color:#dc2626;font-size:12.5px">Could not find Owner column. Headers found: '+esc(hdr.join(', '))+'</p>';
          return;
        }

        // Build Excel map
        const excelMap = {};
        for (let i=1;i<aoa.length;i++) {
          const row=aoa[i];
          const name=String(row[ownerCol]||'').trim();
          if (!name) continue;
          excelMap[name.toLowerCase()] = {
            name,
            pct: pctCol!==-1 ? parseFloat(String(row[pctCol]||'').replace('%',''))||null : null,
            raw: row
          };
        }

        // Compare with Jira
        const jiraMap = {};
        REPORT.rows.forEach(r=>{ jiraMap[r.owner.toLowerCase()]=r; });

        let h=`<table><thead><tr>
          <th>Owner (Excel)</th>
          <th>Excel %</th>
          <th>Jira %</th>
          <th>Match</th>
          <th>Jira Done</th>
          <th>Jira Total</th>
        </tr></thead><tbody>`;

        const allNames = new Set([...Object.keys(excelMap), ...Object.keys(jiraMap)]);
        [...allNames].sort().forEach(n => {
          const ex = excelMap[n];
          const jr = jiraMap[n];
          const displayName = ex?ex.name:(jr?jr.owner:n);
          const exPct = ex?ex.pct:null;
          const jrPct = jr?jr.this_week:null;
          let match='', matchCls='';
          if (exPct!==null&&jrPct!==null) {
            const diff=Math.abs(exPct-jrPct);
            if(diff<1){match='✓ Match';matchCls='cmp-match';}
            else{match=`Diff ${diff.toFixed(1)}%`;matchCls='cmp-diff';}
          } else if(!ex){match='Excel only';matchCls='cmp-missing';}
          else if(!jr){match='Jira only';matchCls='cmp-missing';}
          else{match='No % data';matchCls='cmp-missing';}

          h+=`<tr>
            <td>${esc(displayName)}</td>
            <td class="c">${exPct!==null?exPct+'%':'—'}</td>
            <td class="c">${jrPct!==null?jrPct+'%':'—'}</td>
            <td class="c ${matchCls}">${match}</td>
            <td class="c">${jr?jr.completed:'—'}</td>
            <td class="c">${jr?jr.total:'—'}</td>
          </tr>`;
        });
        wrap.innerHTML = h+'</tbody></table>';
      } catch(err) {
        wrap.innerHTML='<p style="color:#dc2626;font-size:12.5px">Error: '+esc(err.message)+'</p>';
      }
    };
    reader.readAsArrayBuffer(file);
  };
  s.onerror=()=>{wrap.innerHTML='<p style="color:#dc2626;font-size:12.5px">Failed to load XLSX library.</p>';};
  if(!window.XLSX) document.head.appendChild(s);
  else s.onload();
}

// ── canvas image export ────────────────────────────────────────────────────
async function doExportImage(mobile) {
  closeModal('export-modal');
  const secs = {};
  document.querySelectorAll('#exp-sections input[type=checkbox]').forEach(cb=>{
    secs[cb.dataset.sec] = cb.checked;
  });
  const histSel = document.getElementById('exp-hist-week');
  const histIdx = parseInt(histSel.value||'0');
  const histSnaps = (REPORT.history||[]).slice().reverse();
  const histSnap  = histSnaps[histIdx]||null;

  const hasMain = secs.tw || secs.lw || secs.ch || secs.dash;

  if (!hasMain && !secs.hist) {
    toast('Select at least one section to export.'); return;
  }

  // History exported as a separate file (it's a different week's data)
  if (secs.hist && histSnap) {
    const prev = histSnaps[histIdx + 1] || null;
    exportSnapshotImage(histSnap, prev);
  }

  // Main image: live DOM capture — Dashboard on top, tables below.
  // ALL selected sections combined into ONE image (user request).
  if (hasMain) {
    toast('Capturing dashboard view…');
    try {
      const cv = await _captureLiveDashboard(secs);
      if (!cv) { toast('Nothing to capture.'); return; }
      const fn = `progress-${REPORT.date}.png`;
      mobile ? await _shareCanvasMobile(cv, fn) : await _shareOrDownloadCanvas(cv, fn, '✓ Image saved.');
    } catch(e) {
      toast('Export failed: '+e.message); console.error(e);
    }
  }
}

function _drawCanvas(secs, histSnap, hidden, returnCanvas) {
  const rows   = REPORT.rows.filter(r=>!hidden||!hidden.has(r.owner));
  const SCALE  = 2;
  const PAD    = 44;
  const RH     = 42;     // bigger row height
  const HDR    = 50;     // bigger header
  const SEC_H  = 36;
  const TITLE_H = 80;
  const STATS_H = 76;

  // Same column structure as the dashboard
  const TW_COLS = [240,72,72,96,82,90,90,90,170]; // Owner,T,O,IP,WFA,Ov,Done,%,Bar
  const TW_W = TW_COLS.reduce((a,b)=>a+b,0);
  const LW_COLS = [...TW_COLS];
  const LW_W = LW_COLS.reduce((a,b)=>a+b,0);
  const CH_COLS = [280, 140, 380];                  // Owner, Completion%, BiDir Bar
  const CH_W = CH_COLS.reduce((a,b)=>a+b,0);

  // compute sections + measure widths
  let sections = [];
  if (secs.tw) sections.push({type:'tw', h: HDR+(rows.length+1)*RH, w: TW_W, cols: TW_COLS, label:'THIS WEEK  ·  '+formatDateLong(REPORT.date)});
  if (secs.lw) sections.push({type:'lw', h: HDR+(rows.length+1)*RH, w: LW_W, cols: LW_COLS, label:'LAST WEEK  ·  '+formatDateLong(REPORT.last_snap_date)});
  if (secs.ch) sections.push({type:'ch', h: HDR+(rows.length+1)*RH, w: CH_W, cols: CH_COLS, label:'CHANGES  ·  Week over week'});
  if (secs.hist && histSnap) {
    const hp = Object.keys(histSnap.people||{});
    const histW = 160 + 120 + hp.length*100;
    sections.push({type:'hist', snap: histSnap, people:hp, h:HDR+RH, w:histW, label:'HISTORY SNAPSHOT · '+histSnap.date});
  }

  if (sections.length === 0) { toast('Select at least one section to export.'); return; }

  // Canvas width = widest section + padding (no more right-side gap)
  const CW = Math.max(...sections.map(s=>s.w), 800);  // min 800px
  const CANVAS_W = CW + PAD*2;

  // Stretch every section to the canvas width so each table fills the row.
  // For TW/LW: expand the last (Owner's Progress) column.
  // For CH: expand the bidirectional bar column.
  sections.forEach(sec => {
    if (sec.type === 'hist') return;
    if (sec.w < CW) {
      const extra = CW - sec.w;
      sec.cols = sec.cols.slice();
      sec.cols[sec.cols.length - 1] += extra;
      sec.w = CW;
    }
  });

  const totalH = PAD + TITLE_H + STATS_H + 14 +
    sections.reduce((s,x)=>s+SEC_H+x.h+18,0) + PAD;

  const cv = document.createElement('canvas');
  cv.width  = CANVAS_W * SCALE;
  cv.height = totalH * SCALE;
  const c = cv.getContext('2d');
  c.scale(SCALE, SCALE);

  // background
  const bg = c.createLinearGradient(0,0,CANVAS_W,totalH);
  bg.addColorStop(0,'#dbeafe'); bg.addColorStop(.5,'#f0f6ff'); bg.addColorStop(1,'#f0fdf4');
  c.fillStyle=bg; c.fillRect(0,0,CANVAS_W,totalH);

  let y = PAD;

  // Title with prominent date badge
  c.fillStyle='#0f172a'; c.font=`bold 28px Inter,Arial,sans-serif`; c.textAlign='left';
  c.fillText('FIBTMP Progress Report', PAD, y+30);

  // "Last Updated" badge (right side)
  const badgeText = `${REPORT.date} ${_nowHM()}`;
  c.font=`bold 14px "JetBrains Mono",monospace`;
  const badgeW = c.measureText(badgeText).width + 100;
  const badgeX = CANVAS_W - PAD - badgeW;
  c.fillStyle='#dbeafe'; _rr(c,badgeX,y+4,badgeW,38,10); c.fill();
  c.strokeStyle='#93c5fd'; c.lineWidth=1.5; _rr(c,badgeX,y+4,badgeW,38,10); c.stroke();
  c.fillStyle='#1e40af'; c.font=`bold 9px Inter,Arial`;
  c.fillText('LAST UPDATED', badgeX+14, y+19);
  c.fillStyle='#0f172a'; c.font=`bold 14px "JetBrains Mono",monospace`;
  c.fillText(badgeText, badgeX+14, y+35);

  c.fillStyle='#64748b'; c.font=`13px Inter,Arial`; c.textAlign='left';
  c.fillText(`Project Management Office · Generated ${REPORT.date} ${_nowHM()}`, PAD, y+54);
  y += TITLE_H;

  // Stats bar (larger cards)
  const stats = [
    ['This Period', REPORT.team_total+'%', REPORT.team_delta>0?'#059669':REPORT.team_delta<0?'#dc2626':'#1e293b'],
    ['Last Period', REPORT.team_last_week!=null?REPORT.team_last_week+'%':'—','#64748b'],
    ['Change', REPORT.team_delta!=null?(REPORT.team_delta>0?'+':'')+REPORT.team_delta+'%':'—',
               REPORT.team_delta>0?'#059669':REPORT.team_delta<0?'#dc2626':'#64748b'],
    ['Members', String(rows.length),'#2563eb'],
    ['Total Tasks', String(REPORT.grand_total||0),'#334155'],
    ['Overdue', String(rows.reduce((s,r)=>s+(r.overdue||0),0)),'#dc2626'],
  ];
  const SW = Math.floor(CW/stats.length);
  stats.forEach((st,i)=>{
    const sx=PAD+i*SW;
    c.fillStyle='#ffffffcc'; _rr(c,sx,y,SW-8,66,12); c.fill();
    c.strokeStyle='#e2e8f0'; c.lineWidth=1.5; _rr(c,sx,y,SW-8,66,12); c.stroke();
    c.fillStyle='#94a3b8'; c.font=`bold 10px Inter,Arial`; c.textAlign='left';
    c.fillText(st[0].toUpperCase(), sx+12, y+19);
    c.fillStyle=st[2]; c.font=`bold 26px Inter,Arial`;
    c.fillText(st[1], sx+12, y+52);
  });
  y += STATS_H + 14;

  // Sections
  sections.forEach(sec => {
    // Section label with the date prominently bolded
    c.fillStyle='#334155'; c.font=`bold 14px Inter,Arial`; c.textAlign='left';
    c.fillText(sec.label, PAD, y+20); y+=SEC_H;

    _drawTable(c, sec, rows, y, PAD, RH, HDR);
    y += sec.h + 18;
  });

  // Footer
  c.fillStyle='#94a3b8'; c.font=`12px "JetBrains Mono",monospace`; c.textAlign='left';
  c.fillText(`Generated ${REPORT.date} ${_nowHM()} · FIBTMP PMO · ${rows.length} members`, PAD, y+18);

  if (returnCanvas) return cv;
  _shareOrDownloadCanvas(cv, `progress-${REPORT.date}.png`, '✓ Image saved.');
}

function _drawTable(c, sec, rows, y, PAD, RH, HDR) {
  const cols = sec.cols;
  const W = sec.w;

  const HEADS_MAP = {
    tw:  ['Owner','Total','Open','In Progress','Waiting For Approval','Overdue','Completed','Completion %','Owner\'s Progress'],
    lw:  ['Owner','Total','Open','In Progress','Waiting For Approval','Overdue','Completed','Completion %','Owner\'s Progress'],
    ch:  ['Owner','Completion Rate','Week-over-Week Change'],
    hist:['Date','Team %'],
  };

  let heads = HEADS_MAP[sec.type] || [];
  if (sec.type==='hist') { heads = ['Date','Team %',...(sec.people||[]).map(p=>p.length>10?p.slice(0,9)+'…':p)]; }

  // header bg
  c.fillStyle='#e8eef5'; c.fillRect(PAD,y,W,HDR);
  c.strokeStyle='#cbd5e1'; c.lineWidth=1.5; c.strokeRect(PAD,y,W,HDR);

  // header text
  c.fillStyle='#475569'; c.font=`bold 11.5px Inter,Arial`;
  let cx=PAD;
  heads.forEach((h,i)=>{
    const cw2 = sec.type==='hist' ? (i<2?160:100) : (cols[i]||0);
    const tx = i===0 ? cx+12 : cx+cw2/2;
    c.textAlign = i===0?'left':'center';
    c.fillText((h||'').toUpperCase(), tx, y+HDR/2+5);
    cx+=cw2;
  });
  c.textAlign='left'; y+=HDR;

  // data rows
  const drawRows = sec.type==='hist' ? [{_hist:true}] : [...rows, null];

  if (sec.type==='hist' && sec.snap) {
    // single history snapshot row
    const snap=sec.snap;
    c.fillStyle='#ffffff'; c.fillRect(PAD,y,W,RH);
    c.strokeStyle='#e2e8f0'; c.lineWidth=.5;
    c.beginPath(); c.moveTo(PAD,y+RH); c.lineTo(PAD+W,y+RH); c.stroke();
    c.fillStyle='#334155'; c.font=`13px "JetBrains Mono",monospace`; c.textAlign='left';
    c.fillText(snap.date, PAD+12, y+RH/2+5);
    c.fillStyle='#1e293b'; c.font=`bold 14px "JetBrains Mono",monospace`; c.textAlign='center';
    c.fillText(`${snap.team_total}%`, PAD+160+60, y+RH/2+5);
    (sec.people||[]).forEach((p,i)=>{
      const v=(snap.people||{})[p]; const pct=v===undefined?null:(typeof v==='object'?v.pct:v);
      c.fillStyle=pct===null?'#cbd5e1':'#334155';
      c.fillText(pct!==null?`${pct}%`:'—', PAD+160+120+(i+.5)*100, y+RH/2+5);
    });
    return;
  }

  rows.forEach((r, ri) => {
    const isTotal = r===null;
    if (isTotal) {
      r={owner:'TOTAL',total:rows.reduce((s,x)=>s+(x.total||0),0),open:rows.reduce((s,x)=>s+(x.open||0),0),
         in_progress:rows.reduce((s,x)=>s+(x.in_progress||0),0),waiting_for_approval:rows.reduce((s,x)=>s+(x.waiting_for_approval||0),0),
         overdue:rows.reduce((s,x)=>s+(x.overdue||0),0),completed:rows.reduce((s,x)=>s+(x.completed||0),0),
         this_week:REPORT.team_total,last_week:REPORT.team_last_week,delta:REPORT.team_delta};
    }

    const d=r.delta,tw=r.this_week; const isNew=d===null||d===undefined;
    let rowBg=ri%2===0?'#ffffff':'#f8fafc';
    if(!isTotal){if(!isNew&&d>0)rowBg='#f0fdf4';else if(!isNew&&(d<0||(d===0&&tw<100)))rowBg='#fff5f5';}
    if(isTotal)rowBg='#fef9c3';   // yellow TOTAL
    c.fillStyle=rowBg; c.fillRect(PAD,y,W,RH);
    c.strokeStyle = isTotal?'#fde047':'#e2e8f0'; c.lineWidth=isTotal?2:.5;
    if (isTotal) c.strokeRect(PAD, y, W, RH);
    else { c.beginPath(); c.moveTo(PAD,y+RH); c.lineTo(PAD+W,y+RH); c.stroke(); }

    let px=PAD;
    // owner
    c.fillStyle=isTotal?'#0f172a':'#1e293b';
    c.font=isTotal?`bold 14px Inter,Arial`:`13.5px Inter,Arial`; c.textAlign='left';
    const nm=r.owner.length>26?r.owner.slice(0,24)+'…':r.owner;
    c.fillText(nm, px+12, y+RH/2+5); px+=cols[0];

    if (sec.type==='ch') {
      // 3-column changes: Owner | Completion% | Bidirectional bar
      const twv = r.this_week||0;
      // completion %
      const pctC = isNew||isTotal?'#2563eb':d>0?'#059669':d<0||(d===0&&twv<100)?'#dc2626':'#0f172a';
      c.fillStyle=pctC; c.font=`bold 16px "JetBrains Mono",monospace`; c.textAlign='center';
      c.fillText(`${twv}%`, px+cols[1]/2, y+RH/2+6);
      px += cols[1];

      // bidirectional bar
      const barW = cols[2]-30, barH = 24, barX = px+15, barY = y+RH/2-barH/2;
      c.fillStyle='#f8fafc'; _rr(c,barX,barY,barW,barH,5); c.fill();
      c.strokeStyle='#e2e8f0'; c.lineWidth=1; _rr(c,barX,barY,barW,barH,5); c.stroke();
      // center line
      c.fillStyle='#94a3b8'; c.fillRect(barX+barW/2-1, barY, 2, barH);

      let label='', labelColor='#334155';
      if (isNew) {
        label='New baseline'; labelColor='#92400e';
      } else if (d>0) {
        const w = Math.min(50, d)/100*barW;
        const grad=c.createLinearGradient(barX+barW/2,0,barX+barW/2+w,0);
        grad.addColorStop(0,'#86efac'); grad.addColorStop(1,'#10b981');
        c.fillStyle=grad; c.fillRect(barX+barW/2, barY, w, barH);
        label=`+${d}%`; labelColor='#065f46';
      } else if (d<0) {
        const w = Math.min(50, Math.abs(d))/100*barW;
        const grad=c.createLinearGradient(barX+barW/2-w,0,barX+barW/2,0);
        grad.addColorStop(0,'#fca5a5'); grad.addColorStop(1,'#dc2626');
        c.fillStyle=grad; c.fillRect(barX+barW/2-w, barY, w, barH);
        label=`${d}%`; labelColor='#991b1b';
      } else {
        if (twv>=100) { label='Completed'; labelColor='#334155'; }
        else {
          // stuck — RED TEXT ONLY (no bar fill)
          label='0%'; labelColor='#dc2626';
        }
      }
      c.fillStyle=labelColor; c.font=`bold 13px "JetBrains Mono",monospace`; c.textAlign='center';
      c.fillText(label, barX+barW/2, barY+barH/2+5);
    } else {
      // TW or LW: numeric cols
      const vals=sec.type==='tw'
        ? [null,r.total,r.open,r.in_progress,r.waiting_for_approval,r.overdue,r.completed,r.this_week,0]
        : [null,r.last_total||0,r.last_open||0,r.last_in_progress||0,r.last_wfa||0,r.last_overdue||0,r.last_completed||0,r.last_week||0,0];

      for(let i=1;i<=6;i++){
        const n=vals[i]||0; const cw2=cols[i];
        c.textAlign='center';
        if(i===5&&n>0){
          // overdue badge — number only, red bg, no emoji
          c.font=`bold 13px "JetBrains Mono",monospace`;
          const txt = String(n);
          const bw = c.measureText(txt).width + 18;
          c.fillStyle='#fee2e2'; _rr(c,px+cw2/2-bw/2,y+RH/2-12,bw,22,5); c.fill();
          c.fillStyle='#991b1b'; c.fillText(txt,px+cw2/2,y+RH/2+5);
        } else {
          // Black for all numbers including zeros (no more gray zeros)
          c.fillStyle = (i===1||i===6) ? '#0f172a' : '#1e293b';
          c.font = (i===1||i===6) ? `bold 13.5px "JetBrains Mono",monospace`
                                  : `13px "JetBrains Mono",monospace`;
          c.fillText(String(n),px+cw2/2,y+RH/2+5);
        }
        px+=cw2;
      }
      // pct
      const pctVal=vals[7]; const pctCw=cols[7];
      const pctC = isTotal?'#0f172a':'#0f172a';  // always black
      c.fillStyle=pctC; c.font=`bold 14px "JetBrains Mono",monospace`; c.textAlign='center';
      c.fillText(`${pctVal}%`, px+pctCw/2, y+RH/2+5);
      px+=pctCw;

      // Owner's Progress bar (separate column, matches dashboard)
      const bcol = sec.type==='lw' ? ['#d4a574','#92400e'] : ['#34d399','#059669'];
      const barW2=cols[8]-24, barH2=12, barX2=px+12, barY2=y+RH/2-barH2/2;
      c.fillStyle='#f1f5f9'; _rr(c,barX2,barY2,barW2,barH2,3); c.fill();
      c.strokeStyle='#e2e8f0'; c.lineWidth=1; _rr(c,barX2,barY2,barW2,barH2,3); c.stroke();
      const fw = barW2*(Math.min(100,pctVal||0)/100);
      if (fw>0) {
        const gr=c.createLinearGradient(barX2,0,barX2+fw,0);
        gr.addColorStop(0,bcol[0]); gr.addColorStop(1,bcol[1]);
        c.fillStyle=gr; _rr(c,barX2,barY2,fw,barH2,3); c.fill();
      }
    }
    y+=RH;
  });
}

function _rr(c,x,y,w,h,r){
  if(w<=0||h<=0)return;
  r=Math.min(r,w/2,h/2);
  c.beginPath();c.moveTo(x+r,y);c.arcTo(x+w,y,x+w,y+h,r);
  c.arcTo(x+w,y+h,x,y+h,r);c.arcTo(x,y+h,x,y,r);c.arcTo(x,y,x+w,y,r);c.closePath();
}

// ── Compare Periods (PMO Demo Mode) ────────────────────────────────────────
function openCompareModeModal(){
  const hist = REPORT.history||[];
  if (hist.length < 2) {
    toast('Need at least 2 history snapshots to compare. Wait for Sunday saves.');
    return;
  }
  const opts = hist.slice().reverse().map((s,i)=>`<option value="${i}">${s.date}${i===0?' (latest)':''}</option>`).join('');
  document.getElementById('cmp-a').innerHTML = opts;
  document.getElementById('cmp-b').innerHTML = opts;
  document.getElementById('cmp-a').value = Math.min(1, hist.length-1);
  document.getElementById('cmp-b').value = 0;
  renderPeriodCompare();
  openModal('compare-mode-modal');
}

function renderPeriodCompare(){
  const hist = (REPORT.history||[]).slice().reverse();
  const a = hist[parseInt(document.getElementById('cmp-a').value||0)];
  const b = hist[parseInt(document.getElementById('cmp-b').value||0)];
  if (!a || !b) return;

  // Recompute team totals from people, excluding currently-hidden members.
  // Stored snap.team_total was frozen with the hidden list at save time
  // and is now stale, leading to wrong signs in the comparison header.
  const _hide = (hiddenPeople && hiddenPeople.size) ? hiddenPeople : null;
  const _team = (peopleObj) => {
    let tot=0, done=0;
    Object.entries(peopleObj||{}).forEach(([n,p]) => {
      if (_hide && _hide.has(n)) return;
      const v = (typeof p === 'object') ? p : {};
      tot  += v.total || 0;
      done += (v.done != null ? v.done : (v.completed || 0));
    });
    return tot ? Math.round(1000*done/tot)/10 : 0;
  };
  const aTeam = _team(a.people);
  const bTeam = _team(b.people);
  const teamDiff = Math.round((bTeam - aTeam)*10)/10;
  const teamCls = teamDiff>0?'cmp-match':teamDiff<0?'cmp-diff':'';
  const teamTxt = teamDiff>0?`+${teamDiff}%`:teamDiff===0?'0%':`${teamDiff}%`;

  const allPeople = [...new Set([...Object.keys(a.people||{}), ...Object.keys(b.people||{})])]
    .filter(n => !_hide || !_hide.has(n))
    .sort();

  let h = `<div style="background:linear-gradient(135deg,#dbeafe,#ede9fe);border:1.5px solid #bfdbfe;border-radius:12px;padding:14px 18px;margin-bottom:14px;display:flex;align-items:center;gap:18px;flex-wrap:wrap">
    <div>
      <div style="font-size:10px;font-weight:800;color:#1e40af;letter-spacing:.1em">${a.date} → ${b.date}</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:22px;font-weight:800;color:#0f172a;margin-top:2px">
        ${aTeam}% → ${bTeam}%
      </div>
    </div>
    <div style="margin-left:auto;font-family:'JetBrains Mono',monospace;font-size:24px;font-weight:800"
         class="${teamCls}">${teamTxt}</div>
  </div>`;

  h += `<table style="min-width:600px"><thead><tr>
    <th>Owner</th>
    <th class="c">${a.date}</th>
    <th class="c">${b.date}</th>
    <th class="c">Change %</th>
    <th class="c">Done diff</th>
    <th class="c">Overdue diff</th>
  </tr></thead><tbody>`;

  allPeople.forEach(p => {
    const pa = (a.people||{})[p]; const pb = (b.people||{})[p];
    const pctA = pa ? (typeof pa==='object'?pa.pct:pa) : null;
    const pctB = pb ? (typeof pb==='object'?pb.pct:pb) : null;
    const dDone = (pb&&pa&&typeof pa==='object'&&typeof pb==='object') ? (pb.done||0)-(pa.done||0) : null;
    const dOv   = (pb&&pa&&typeof pa==='object'&&typeof pb==='object') ? (pb.overdue||0)-(pa.overdue||0) : null;
    const pctD  = (pctA!==null&&pctB!==null) ? Math.round((pctB-pctA)*10)/10 : null;
    const pctCls = pctD===null?'':pctD>0?'cmp-match':pctD<0?'cmp-diff':'';
    h += `<tr>
      <td style="font-weight:700">${esc(p)}</td>
      <td class="c">${pctA!==null?pctA+'%':'—'}</td>
      <td class="c">${pctB!==null?pctB+'%':'—'}</td>
      <td class="c ${pctCls}">${pctD===null?'—':(pctD>0?'+':'')+pctD+'%'}</td>
      <td class="c">${dDone===null?'—':(dDone>0?'+':'')+dDone}</td>
      <td class="c" style="${dOv>0?'color:#dc2626;font-weight:700':''}">${dOv===null?'—':(dOv>0?'+':'')+dOv}</td>
    </tr>`;
  });
  document.getElementById('cmp-mode-result').innerHTML = h + '</tbody></table>';
}

// ── AI Insights Image Export ───────────────────────────────────────────────
function exportAIImage(){
  toast('Generating AI insights image…');
  setTimeout(()=>{
    try { _drawAICanvas(); }
    catch(e){ toast('Export failed: '+e.message); console.error(e); }
  }, 50);
}

function _drawAICanvas(){
  const SCALE = 2;
  const W = 900, PAD = 36;
  const risks = (ANALYSIS.risks||[]).filter(r=>r&&r.name);
  const summary = ANALYSIS.summary || '(no summary)';

  // Pre-measure summary text height
  const tmpC = document.createElement('canvas').getContext('2d');
  tmpC.font = '16px Inter, Arial, sans-serif';
  const lineHeight = 26;
  const wrapWidth = W - PAD*2 - 24;
  const summaryLines = _wrapText(tmpC, summary, wrapWidth);
  const summaryH = summaryLines.length * lineHeight + 30;

  // Risk cards: 2 columns, ~140px each (with notes wrapped)
  const cardW = (W - PAD*2 - 12) / 2;
  let cardHeights = [];
  risks.forEach(r => {
    tmpC.font = '14px Inter, Arial';
    const noteLines = _wrapText(tmpC, r.note||'', cardW - 28);
    tmpC.font = '13px Inter, Arial';
    const tipLines = r.tip ? _wrapText(tmpC, r.tip, cardW - 36) : [];
    cardHeights.push(38 + noteLines.length*20 + (tipLines.length ? 12+tipLines.length*19 : 0) + 14);
  });
  let rowHeights = [];
  for(let i=0;i<cardHeights.length;i+=2) {
    rowHeights.push(Math.max(cardHeights[i]||0, cardHeights[i+1]||0));
  }
  const risksH = risks.length ? 36 + rowHeights.reduce((a,b)=>a+b+10,0) : 0;
  const H = PAD + 56 + summaryH + risksH + PAD;

  const cv = document.createElement('canvas');
  cv.width = W*SCALE; cv.height = H*SCALE;
  const c = cv.getContext('2d'); c.scale(SCALE,SCALE);

  const bg = c.createLinearGradient(0,0,W,H);
  bg.addColorStop(0,'#dbeafe'); bg.addColorStop(.5,'#f0f6ff'); bg.addColorStop(1,'#f0fdf4');
  c.fillStyle=bg; c.fillRect(0,0,W,H);

  let y = PAD;
  // header
  c.fillStyle='#2563eb'; c.font='bold 20px Inter, Arial'; c.textAlign='left';
  c.fillText('🤖 AI Analysis & Risk Flags', PAD, y+20);
  c.fillStyle='#64748b'; c.font='12px "JetBrains Mono", monospace';
  c.fillText(`FIBTMP · ${REPORT.date}`, PAD, y+40); y+=58;

  // summary card
  c.fillStyle='#ffffff'; _rr(c,PAD,y,W-PAD*2,summaryH,12); c.fill();
  c.strokeStyle='#bfdbfe'; c.lineWidth=1.5; _rr(c,PAD,y,W-PAD*2,summaryH,12); c.stroke();
  c.fillStyle='#1e40af'; c.font='bold 10px Inter,Arial';
  c.fillText('SUMMARY', PAD+14, y+18);
  c.fillStyle='#334155'; c.font='16px Inter, Arial';
  summaryLines.forEach((ln,i)=> c.fillText(ln, PAD+14, y+38+i*lineHeight));
  y += summaryH + 18;

  // risks
  if (risks.length) {
    c.fillStyle='#b45309'; c.font='bold 12px Inter,Arial';
    c.fillText(`RISK FLAGS (${risks.length})`, PAD, y+14); y+=28;
    let rowIdx = 0;
    for (let i=0;i<risks.length;i+=2) {
      const rh = rowHeights[rowIdx++];
      for (let j=0;j<2 && (i+j)<risks.length; j++) {
        const r = risks[i+j];
        const cx = PAD + j*(cardW+12);
        c.fillStyle='#fffbeb'; _rr(c,cx,y,cardW,rh,10); c.fill();
        c.strokeStyle='#fde68a'; c.lineWidth=1.5; _rr(c,cx,y,cardW,rh,10); c.stroke();
        c.fillStyle='#92400e'; c.font='bold 14px Inter,Arial';
        c.fillText((r.name||''), cx+14, y+20);
        c.fillStyle='#78350f'; c.font='14px Inter,Arial';
        const nl = _wrapText(c, r.note||'', cardW-28);
        nl.forEach((ln,k)=> c.fillText(ln, cx+14, y+42+k*20));
        if (r.tip) {
          const ty = y + 42 + nl.length*20 + 8;
          const tl = _wrapText(c, r.tip, cardW-36);
          c.fillStyle='#ecfdf5'; _rr(c,cx+10,ty-12,cardW-20,tl.length*19+12,6); c.fill();
          c.strokeStyle='#a7f3d0'; c.lineWidth=1; _rr(c,cx+10,ty-12,cardW-20,tl.length*19+12,6); c.stroke();
          c.fillStyle='#065f46'; c.font='13px Inter,Arial';
          tl.forEach((ln,k)=> c.fillText('💡 '+ln, cx+18, ty+k*19));
        }
      }
      y += rh + 10;
    }
  }

  c.fillStyle='#94a3b8'; c.font='10px "JetBrains Mono",monospace';
  c.fillText(`Generated ${REPORT.date} ${_nowHM()} · FIBTMP PMO`, PAD, H-14);

  _shareOrDownloadCanvas(cv, `ai-insights-${REPORT.date}.png`, '✓ AI insights image saved.');
}

function _wrapText(ctx, text, maxWidth) {
  const words = (text||'').split(/\s+/);
  const lines = []; let line = '';
  words.forEach(w => {
    const t = line ? line+' '+w : w;
    if (ctx.measureText(t).width > maxWidth && line) { lines.push(line); line = w; }
    else { line = t; }
  });
  if (line) lines.push(line);
  return lines;
}

// ── Baseline selector (let the user pick which snapshot = "Last Week") ─────
let _ORIGINAL_REPORT = null;  // snapshot of REPORT after first init (auto baseline)
let _WEEKLY_DAY = null;       // configured weekly baseline day (Sun=0..Sat=6) from schedule.json
let _PINNED_BASELINE = null;  // admin-pinned baseline date (YYYY-MM-DD) from schedule.json
async function _loadWeeklyDay(){
  const repo = document.querySelector('meta[name=repo]')?.content||'';
  if(!repo) return;
  try{
    const r=await fetch(`https://raw.githubusercontent.com/${repo}/main/data/schedule.json?t=${Date.now()}`,{cache:'no-store'});
    if(!r.ok) return;
    const cfg=await r.json();
    if(!cfg) return;
    if(cfg.weekly_day!=null) _WEEKLY_DAY=cfg.weekly_day;
    _PINNED_BASELINE = cfg.pinned_baseline || null;
    // Rebuild so findBaseline applies the pin / weekly-day across refreshes.
    if(typeof refreshLive==='function' && GH_PROXY) refreshLive();
    else if(typeof REPORT!=='undefined'&&REPORT) populateBaselineSelector();
  }catch(e){}
}

function populateBaselineSelector() {
  const sel    = document.getElementById('baseline-sel');
  const selTop = document.getElementById('baseline-sel-top');
  if (!sel && !selTop) return;
  const hist = REPORT.history || [];
  // include ALL snapshots (today included) so user can pick today as baseline
  const candidates = hist.slice().reverse();
  const current = REPORT.last_snap_date || '';

  // Label reflects the CONFIGURED weekly day (admin / pencil → schedule.json),
  // falling back to the weekday of the most recent weekly snapshot.
  const _DOW = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
  let autoLabel = 'Auto · last weekly';
  if (_WEEKLY_DAY !== null && _WEEKLY_DAY >= 0 && _WEEKLY_DAY <= 6) {
    autoLabel = 'Auto · last ' + _DOW[_WEEKLY_DAY];
  } else {
    const _lastWeekly = hist.filter(s => s.is_weekly).pop();
    if (_lastWeekly && _lastWeekly.date) {
      const _d = new Date(_lastWeekly.date + 'T00:00:00');
      if (!isNaN(_d)) autoLabel = 'Auto · last ' + _DOW[_d.getDay()];
    }
  }
  // Resolve the pin to a concrete date: "latest" → newest snapshot before today.
  const _pinIsLatest = _PINNED_BASELINE && String(_PINNED_BASELINE).toLowerCase()==='latest';
  let _pinDate = _PINNED_BASELINE;
  if (_pinIsLatest) {
    const prior = hist.filter(s => (s.date||'') < REPORT.date);
    _pinDate = prior.length ? prior[prior.length-1].date : null;
  }
  let opts = '<option value="auto"' + (current && hist.find(s=>s.date===current&&s.is_weekly) ? ' selected':'') + '>' + autoLabel + '</option>';
  candidates.forEach(s => {
    const isToday = s.date === REPORT.date;
    const label = formatDateTime(s.timestamp || s.date)
                  + (isToday ? ' (today)' : (s.is_weekly ? ' (weekly)' : ''))
                  + (s.date===_pinDate ? (_pinIsLatest ? '  *PINNED · latest*' : '  *PINNED*') : '');
    opts += `<option value="${s.date}" ${s.date===current ? 'selected':''}>${label}</option>`;
  });
  if (!candidates.length) {
    opts = '<option value="auto">No baselines yet — first save creates one</option>';
  }
  if (sel)    sel.innerHTML = opts;
  if (selTop) selTop.innerHTML = opts;
}

// ── Change the weekly "Auto" baseline day from the dashboard (admin-gated) ──
const _DOW_FULL = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
function _pickWeeklyDay(cur){
  return new Promise(resolve=>{
    let ov=document.getElementById('daypick-overlay');
    if(!ov){
      ov=document.createElement('div'); ov.id='daypick-overlay';
      ov.style.cssText='position:fixed;inset:0;background:rgba(15,23,42,.55);backdrop-filter:blur(6px);display:none;align-items:center;justify-content:center;z-index:9999;font-family:Inter,system-ui,sans-serif';
      ov.innerHTML='<div style="background:#fff;border-radius:16px;padding:24px;width:min(320px,92vw);box-shadow:0 20px 60px rgba(15,23,42,.3)">'
        +'<div style="font-weight:800;font-size:16px;margin-bottom:4px;color:#0f172a">Weekly baseline day</div>'
        +'<div style="color:#64748b;font-size:12.5px;margin-bottom:12px">The snapshot saved on this day becomes the &quot;Auto&quot; baseline.</div>'
        +'<select id="daypick-sel" style="width:100%;border:1.5px solid #e2e8f0;border-radius:8px;padding:9px;font-size:14px;margin-bottom:14px">'
        +_DOW_FULL.map((d,i)=>'<option value="'+i+'">'+d+'</option>').join('')+'</select>'
        +'<div style="display:flex;gap:8px;justify-content:flex-end">'
        +'<button id="daypick-cancel" style="border:1px solid #e2e8f0;background:#fff;border-radius:8px;padding:8px 14px;font-weight:600;cursor:pointer">Cancel</button>'
        +'<button id="daypick-ok" style="border:none;background:#0d9488;color:#fff;border-radius:8px;padding:8px 16px;font-weight:700;cursor:pointer">Save</button></div></div>';
      document.body.appendChild(ov);
    }
    const sel=ov.querySelector('#daypick-sel'); sel.value=String(cur);
    ov.style.display='flex';
    ov.querySelector('#daypick-ok').onclick=()=>{ov.style.display='none';resolve(parseInt(sel.value));};
    ov.querySelector('#daypick-cancel').onclick=()=>{ov.style.display='none';resolve(null);};
  });
}
async function editAutoDay(ev){
  if(ev) ev.preventDefault();
  const ok = await _askRestrictedPw();   // admin password, verified server-side
  if(!ok) return;
  const repo = document.querySelector('meta[name=repo]')?.content||'';
  let cfg={}, sha=null;
  try{
    const r=await fetch(`https://api.github.com/repos/${repo}/contents/data/schedule.json?t=${Date.now()}`,{cache:'no-store'});
    const j=await r.json(); sha=j.sha;
    cfg=JSON.parse(decodeURIComponent(Array.from(atob((j.content||'').replace(/\s/g,''))).map(c=>'%'+c.charCodeAt(0).toString(16).padStart(2,'0')).join('')));
  }catch(e){ toast('Could not load schedule.'); return; }
  const cur = (cfg.weekly_day==null)?3:cfg.weekly_day;
  const day = await _pickWeeklyDay(cur);
  if(day===null) return;
  cfg.weekly_day=day; cfg.active_days=[day]; cfg.send_email=false;
  if(!cfg.slots_utc||!cfg.slots_utc.length) cfg.slots_utc=['11:55'];
  cfg.hours_utc=[parseInt(cfg.slots_utc[0].split(':')[0])];
  cfg.description=`Weekly snapshot on ${_DOW_FULL[day]}`;
  const content=btoa(unescape(encodeURIComponent(JSON.stringify(cfg,null,2)+'\n')));
  try{
    const pr=await fetch(`https://api.github.com/repos/${repo}/contents/data/schedule.json`,{
      method:'PUT', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({message:`Set weekly report day to ${_DOW_FULL[day]}`,content,sha})
    });
    if(pr.ok){ _WEEKLY_DAY=day; populateBaselineSelector(); toast('✓ Auto baseline day set to '+_DOW_FULL[day]); }
    else { const j=await pr.json(); toast('Save failed: '+(j.message||pr.status)); }
  }catch(e){ toast('Network error: '+e.message); }
}

// Right-click the baseline chip -> pin the selected snapshot as a persistent,
// password-protected baseline (saved to schedule.json; survives refresh).
function _baselineMenu(ev){
  ev.preventDefault();
  let m=document.getElementById('bl-ctx');
  if(!m){
    m=document.createElement('div'); m.id='bl-ctx';
    m.style.cssText='position:fixed;z-index:10000;background:#fff;border:1px solid #e2e8f0;border-radius:10px;box-shadow:0 12px 32px rgba(15,23,42,.18);padding:6px;font-family:Inter,system-ui,sans-serif;font-size:13px;min-width:220px;display:none';
    document.body.appendChild(m);
    document.addEventListener('click',()=>{m.style.display='none';});
  }
  const sel=document.getElementById('baseline-sel-top');
  const val=sel?sel.value:'';
  const isSpecific = val && val!=='auto';
  const labelTxt = isSpecific ? sel.options[sel.selectedIndex].text : '';
  m.innerHTML='<div style="padding:6px 10px;font-size:11px;color:#94a3b8;font-weight:700;letter-spacing:.08em">BASELINE - ADMIN</div>'
    +'<div class="blc-item" data-act="latest" style="padding:8px 10px;border-radius:6px;cursor:pointer">Pin <b>latest snapshot</b> (auto-follows newest)</div>'
    +(isSpecific?'<div class="blc-item" data-act="pin" style="padding:8px 10px;border-radius:6px;cursor:pointer">Pin \''+esc(labelTxt)+'\' as baseline</div>'
                :'<div style="padding:8px 10px;color:#94a3b8;font-size:12px">Select a specific snapshot to pin that exact date.</div>')
    +'<div class="blc-item" data-act="clear" style="padding:8px 10px;border-radius:6px;cursor:pointer">Clear pin (use Auto)</div>';
  m.querySelectorAll('.blc-item').forEach(el=>{
    el.onmouseenter=()=>el.style.background='#f1f5f9'; el.onmouseleave=()=>el.style.background='';
    el.onclick=(e)=>{ e.stopPropagation(); m.style.display='none';
      const act=el.dataset.act;
      if(act==='latest') pinBaseline(false,'latest');
      else pinBaseline(act==='clear', isSpecific?val:null); };
  });
  m.style.left=Math.min(ev.clientX, window.innerWidth-240)+'px';
  m.style.top=Math.min(ev.clientY, window.innerHeight-130)+'px';
  m.style.display='block';
  return false;
}
async function pinBaseline(clear, val){
  const ok=await _askRestrictedPw(); if(!ok) return;       // admin password (server-verified)
  if(!clear && !val){ toast('Pick a specific snapshot first, then pin it.'); return; }
  const repo=document.querySelector('meta[name=repo]')?.content||'';
  let cfg={}, sha=null;
  try{
    const r=await fetch('https://api.github.com/repos/'+repo+'/contents/data/schedule.json?t='+Date.now(),{cache:'no-store'});
    const j=await r.json(); sha=j.sha;
    cfg=JSON.parse(decodeURIComponent(Array.from(atob((j.content||'').replace(/\s/g,''))).map(c=>'%'+c.charCodeAt(0).toString(16).padStart(2,'0')).join('')));
  }catch(e){ toast('Could not load schedule.'); return; }
  if(clear) delete cfg.pinned_baseline; else cfg.pinned_baseline=val;
  const content=btoa(unescape(encodeURIComponent(JSON.stringify(cfg,null,2)+'\n')));
  try{
    const pr=await fetch('https://api.github.com/repos/'+repo+'/contents/data/schedule.json',{
      method:'PUT', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({message: clear?'Clear pinned baseline':('Pin baseline '+val), content, sha})
    });
    if(pr.ok){
      _PINNED_BASELINE = clear?null:val;
      toast(clear?'Pin cleared - using Auto':(val==='latest'?'Pinned to latest snapshot - follows every new save':'Baseline pinned: '+val));
      if(typeof refreshLive==='function' && GH_PROXY) refreshLive(); else if(REPORT) populateBaselineSelector();
    } else { const j=await pr.json(); toast('Save failed: '+(j.message||pr.status)); }
  }catch(e){ toast('Network error: '+e.message); }
}

function setBaseline(value) {
  if (!_ORIGINAL_REPORT) _ORIGINAL_REPORT = JSON.parse(JSON.stringify(REPORT));
  const hist = _ORIGINAL_REPORT.history || [];

  let snap = null;
  if (value === 'auto') {
    const prior = hist.filter(s => s.date < _ORIGINAL_REPORT.date);
    // Prefer the most recent PRIOR snapshot on the configured weekly day, so
    // "Auto · last <day>" actually compares against that day once one exists.
    if (_WEEKLY_DAY !== null) {
      const onDay = prior.filter(s => { const d=new Date(s.date+'T00:00:00'); return !isNaN(d) && d.getDay()===_WEEKLY_DAY; });
      if (onDay.length) snap = onDay[onDay.length-1];
    }
    // Fallbacks: most recent weekly-tagged snapshot, then most recent prior.
    if (!snap) {
      const weekly = prior.filter(s => s.is_weekly);
      snap = weekly.length ? weekly[weekly.length-1] : (prior.length ? prior[prior.length-1] : null);
    }
  } else {
    snap = hist.find(s => s.date === value);
  }

  // Recompute rows against chosen baseline
  const newRows = _ORIGINAL_REPORT.rows.map(r => {
    if (!snap) {
      return {...r, last_week:null, last_total:0, last_open:0, last_in_progress:0,
              last_wfa:0, last_overdue:0, last_completed:0, delta:null};
    }
    const prev = (snap.people||{})[r.owner];
    if (prev === undefined || prev === null) {
      return {...r, last_week:null, last_total:0, last_open:0, last_in_progress:0,
              last_wfa:0, last_overdue:0, last_completed:0, delta:null};
    }
    const p = (typeof prev === 'object') ? prev : {pct: prev};
    const pct = p.pct;
    return {
      ...r,
      last_week: pct,
      last_total: p.total||0,
      last_open: p.open||0,
      last_in_progress: p.in_progress||0,
      last_wfa: p.waiting_for_approval||0,
      last_overdue: p.overdue||0,
      last_completed: p.completed||p.done||0,
      delta: (pct!==undefined&&pct!==null) ? Math.round((r.this_week - pct)*10)/10 : null,
    };
  });

  // Recompute team totals — for BOTH today and the baseline — from
  // non-hidden people only. Server-side totals were frozen with the
  // hidden list active at save/build time and may now be stale.
  const teamFromPeopleObj = (peopleObj) => {
    if (!peopleObj) return null;
    let tot = 0, done = 0;
    Object.entries(peopleObj).forEach(([n, p]) => {
      if (hiddenPeople && hiddenPeople.has(n)) return;
      const v = (typeof p === 'object') ? p : {total:0, done:0};
      tot  += v.total || 0;
      done += (v.done != null ? v.done : (v.completed || 0));
    });
    return tot ? Math.round(1000*done/tot)/10 : 0;
  };
  const teamFromRows = (rows) => {
    let tot = 0, done = 0;
    rows.forEach(r => {
      if (hiddenPeople && hiddenPeople.has(r.owner)) return;
      tot  += r.total || 0;
      done += r.completed || 0;
    });
    return tot ? Math.round(1000*done/tot)/10 : 0;
  };
  const todayTeam = teamFromRows(_ORIGINAL_REPORT.rows);
  const snapTeam  = snap ? teamFromPeopleObj(snap.people) : null;

  REPORT = {
    ..._ORIGINAL_REPORT,
    rows: newRows,
    last_snap_date: snap ? snap.date : null,
    last_snap_time: snap ? (snap.timestamp || snap.date) : null,
    team_total: todayTeam,
    team_last_week: snapTeam,
    team_delta: snapTeam !== null
      ? Math.round((todayTeam - snapTeam)*10)/10
      : null,
    has_previous: !!snap,
  };
  init();
  toast('Baseline updated' + (snap ? ' to '+formatDateLong(snap.date) : ' (no baseline)'));
}

// ── Demo Mode (realistic sample week showing good/bad/new/stuck) ───────────
let DEMO_ON = false;
let REAL_REPORT = null, REAL_ANALYSIS = null;

const DEMO_REPORT = {
  date: '2026-05-27',
  last_snap_date: '2026-05-20',
  team_total: 67.2,
  team_last_week: 58.4,
  team_delta: 8.8,
  grand_total: 142,
  grand_done: 95,
  has_previous: true,
  rows: [
    {owner:'Ahmed (Top Performer)', total:18, open:0, in_progress:2, waiting_for_approval:0, overdue:0, completed:16, this_week:88.9, last_week:55.6, delta:33.3,
     last_total:18, last_open:5, last_in_progress:3, last_wfa:0, last_overdue:1, last_completed:10},
    {owner:'Sara (Improving)', total:14, open:2, in_progress:3, waiting_for_approval:1, overdue:0, completed:8, this_week:57.1, last_week:42.9, delta:14.2,
     last_total:14, last_open:4, last_in_progress:3, last_wfa:1, last_overdue:0, last_completed:6},
    {owner:'Omar (Steady High)', total:12, open:0, in_progress:0, waiting_for_approval:0, overdue:0, completed:12, this_week:100, last_week:100, delta:0,
     last_total:12, last_open:0, last_in_progress:0, last_wfa:0, last_overdue:0, last_completed:12},
    {owner:'Lina (Declining)', total:16, open:6, in_progress:2, waiting_for_approval:0, overdue:3, completed:8, this_week:50.0, last_week:75.0, delta:-25.0,
     last_total:16, last_open:2, last_in_progress:1, last_wfa:1, last_overdue:0, last_completed:12},
    {owner:'Yousef (Stuck at 0%)', total:8, open:6, in_progress:2, waiting_for_approval:0, overdue:2, completed:0, this_week:0, last_week:0, delta:0,
     last_total:8, last_open:6, last_in_progress:2, last_wfa:0, last_overdue:0, last_completed:0},
    {owner:'Mariam (New Joiner)', total:9, open:5, in_progress:3, waiting_for_approval:0, overdue:0, completed:1, this_week:11.1, last_week:null, delta:null,
     last_total:0, last_open:0, last_in_progress:0, last_wfa:0, last_overdue:0, last_completed:0},
    {owner:'Hassan (At Risk)', total:11, open:4, in_progress:1, waiting_for_approval:0, overdue:5, completed:6, this_week:54.5, last_week:63.6, delta:-9.1,
     last_total:11, last_open:2, last_in_progress:2, last_wfa:0, last_overdue:1, last_completed:7},
    {owner:'Fatima (Reliable)', total:13, open:1, in_progress:1, waiting_for_approval:0, overdue:0, completed:11, this_week:84.6, last_week:76.9, delta:7.7,
     last_total:13, last_open:2, last_in_progress:1, last_wfa:0, last_overdue:0, last_completed:10},
  ],
  history: [
    {date:'2026-05-06', team_total:42.1, people:{
      'Ahmed (Top Performer)':{pct:30,done:5,total:18,open:8,in_progress:5,waiting_for_approval:0,overdue:2,completed:5,statuses:{}},
      'Sara (Improving)':{pct:35,done:5,total:14,open:5,in_progress:4,waiting_for_approval:0,overdue:1,completed:5,statuses:{}},
      'Omar (Steady High)':{pct:100,done:12,total:12,open:0,in_progress:0,waiting_for_approval:0,overdue:0,completed:12,statuses:{}},
      'Lina (Declining)':{pct:85,done:14,total:16,open:1,in_progress:1,waiting_for_approval:0,overdue:0,completed:14,statuses:{}},
      'Yousef (Stuck at 0%)':{pct:0,done:0,total:8,open:6,in_progress:2,waiting_for_approval:0,overdue:0,completed:0,statuses:{}},
      'Hassan (At Risk)':{pct:72.7,done:8,total:11,open:1,in_progress:2,waiting_for_approval:0,overdue:0,completed:8,statuses:{}},
      'Fatima (Reliable)':{pct:69.2,done:9,total:13,open:3,in_progress:1,waiting_for_approval:0,overdue:0,completed:9,statuses:{}},
    }},
    {date:'2026-05-13', team_total:50.0, people:{
      'Ahmed (Top Performer)':{pct:44.4,done:8,total:18,open:6,in_progress:4,waiting_for_approval:0,overdue:2,completed:8,statuses:{}},
      'Sara (Improving)':{pct:35.7,done:5,total:14,open:5,in_progress:4,waiting_for_approval:0,overdue:1,completed:5,statuses:{}},
      'Omar (Steady High)':{pct:100,done:12,total:12,open:0,in_progress:0,waiting_for_approval:0,overdue:0,completed:12,statuses:{}},
      'Lina (Declining)':{pct:81.3,done:13,total:16,open:1,in_progress:2,waiting_for_approval:0,overdue:0,completed:13,statuses:{}},
      'Yousef (Stuck at 0%)':{pct:0,done:0,total:8,open:6,in_progress:2,waiting_for_approval:0,overdue:1,completed:0,statuses:{}},
      'Hassan (At Risk)':{pct:72.7,done:8,total:11,open:1,in_progress:2,waiting_for_approval:0,overdue:1,completed:8,statuses:{}},
      'Fatima (Reliable)':{pct:76.9,done:10,total:13,open:2,in_progress:1,waiting_for_approval:0,overdue:0,completed:10,statuses:{}},
    }},
    {date:'2026-05-20', team_total:58.4, people:{
      'Ahmed (Top Performer)':{pct:55.6,done:10,total:18,open:5,in_progress:3,waiting_for_approval:0,overdue:1,completed:10,statuses:{}},
      'Sara (Improving)':{pct:42.9,done:6,total:14,open:4,in_progress:3,waiting_for_approval:1,overdue:0,completed:6,statuses:{}},
      'Omar (Steady High)':{pct:100,done:12,total:12,open:0,in_progress:0,waiting_for_approval:0,overdue:0,completed:12,statuses:{}},
      'Lina (Declining)':{pct:75.0,done:12,total:16,open:2,in_progress:1,waiting_for_approval:1,overdue:0,completed:12,statuses:{}},
      'Yousef (Stuck at 0%)':{pct:0,done:0,total:8,open:6,in_progress:2,waiting_for_approval:0,overdue:0,completed:0,statuses:{}},
      'Hassan (At Risk)':{pct:63.6,done:7,total:11,open:2,in_progress:2,waiting_for_approval:0,overdue:1,completed:7,statuses:{}},
      'Fatima (Reliable)':{pct:76.9,done:10,total:13,open:2,in_progress:1,waiting_for_approval:0,overdue:0,completed:10,statuses:{}},
    }},
  ],
};

const DEMO_ANALYSIS = {
  summary: 'Strong team momentum this week — Ahmed and Sara drove an 8.8% team improvement, with Ahmed jumping +33.3% to 88.9% completion. Two members need immediate attention: Lina lost 25% (now 50%, 3 overdue) and Yousef remains stuck at 0% with 2 overdue tasks. Mariam joined as a new member with 11% progress.',
  risks: [
    {name:'Lina (Declining)', note:'Dropped 25% week-over-week with 3 overdue tasks.', tip:'1:1 conversation needed — find out if scope expanded or there are blockers.'},
    {name:'Yousef (Stuck at 0%)', note:'No progress in two weeks, 2 tasks now overdue.', tip:'Re-assign workload or escalate to manager. Likely blocked or disengaged.'},
    {name:'Hassan (At Risk)', note:'Declining trend (-9%), 5 overdue tasks accumulating.', tip:'Break large tasks into smaller deliverables to restore momentum.'},
    {name:'Mariam (New Joiner)', note:'Just joined this week with 9 tasks, 11% done so far.', tip:'Pair with Omar (steady high performer) for onboarding mentorship.'},
  ],
};

function toggleDemoMode(){
  DEMO_ON = !DEMO_ON;
  if (DEMO_ON) {
    REAL_REPORT = REPORT; REAL_ANALYSIS = ANALYSIS;
    REPORT = DEMO_REPORT; ANALYSIS = DEMO_ANALYSIS;
    document.getElementById('demo-btn-txt').textContent = '✕ Exit Demo';
    document.getElementById('demo-btn').style.background='linear-gradient(135deg,#f59e0b,#d97706)';
    document.getElementById('demo-btn').style.color='#fff';
    document.getElementById('demo-btn').style.borderColor='transparent';
    toast('🎬 Demo Mode ON — showing sample data with good/bad/new/stuck members.');
  } else {
    REPORT = REAL_REPORT; ANALYSIS = REAL_ANALYSIS;
    document.getElementById('demo-btn-txt').textContent = 'Demo Mode';
    document.getElementById('demo-btn').style.background='';
    document.getElementById('demo-btn').style.color='';
    document.getElementById('demo-btn').style.borderColor='';
    toast('Back to live data.');
  }
  init();
}

/* ── Laser pointer (presentation mode) ───────────────────────────────────── */
let LASER_ON = false;
(function setupLaser(){
  const dot = document.getElementById('laser-dot');
  const ring = document.getElementById('laser-ring');
  if (!dot) return;
  let x = window.innerWidth / 2, y = window.innerHeight / 2;
  let tx = x, ty = y, raf = null;
  function render(){
    // light smoothing so the dot glides without lagging behind the cursor
    x += (tx - x) * 0.5;
    y += (ty - y) * 0.5;
    dot.style.transform = 'translate(' + x + 'px,' + y + 'px)';
    raf = (Math.abs(tx - x) > 0.3 || Math.abs(ty - y) > 0.3)
      ? requestAnimationFrame(render) : null;
  }
  function onMove(e){
    tx = e.clientX; ty = e.clientY;
    if (raf === null) raf = requestAnimationFrame(render);
  }
  window.addEventListener('mousemove', onMove);
  window.addEventListener('touchmove', function(e){
    if (e.touches && e.touches[0]) onMove(e.touches[0]);
  }, {passive:true});
  // click anywhere → a ring pulses out to draw the eye to that spot
  window.addEventListener('mousedown', function(e){
    if (!LASER_ON || !ring) return;
    ring.style.left = e.clientX + 'px';
    ring.style.top  = e.clientY + 'px';
    ring.classList.remove('pulse'); void ring.offsetWidth; ring.classList.add('pulse');
  });
})();

function toggleLaser(){
  LASER_ON = !LASER_ON;
  document.body.classList.toggle('laser-on', LASER_ON);
  const item = document.getElementById('laser-menu-item');
  const state = document.getElementById('laser-state');
  const fab = document.getElementById('laser-fab');
  const label = document.getElementById('laser-label');
  if (item) item.classList.toggle('active', LASER_ON);
  if (fab) fab.classList.toggle('active', LASER_ON);
  if (state) state.textContent = LASER_ON ? '· ON' : '';
  if (label) label.textContent = LASER_ON ? 'Laser ON' : 'Laser';
  toast(LASER_ON
    ? '🔴 Laser pointer ON — move your mouse. Click to pulse · L or Esc to exit.'
    : 'Laser pointer off.');
}

// keyboard: L toggles, Esc turns off (ignored while typing in a field)
document.addEventListener('keydown', function(e){
  const t = e.target;
  const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);
  if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === 'l' || e.key === 'L') { e.preventDefault(); toggleLaser(); }
  else if (e.key === 'Escape' && LASER_ON) { toggleLaser(); }
});
</script>

<!-- ═══════════════ Theme / background / scroll controls ═══════════════════ -->
<style>
  body.pat-2{background:#f6f8fc !important;
    background-image:radial-gradient(#c7d2fe 1.2px,transparent 1.3px) !important;
    background-size:18px 18px !important}
  body.pat-3{background:#f7faf9 !important;
    background-image:linear-gradient(#d9e7e4 1px,transparent 1px),linear-gradient(90deg,#d9e7e4 1px,transparent 1px) !important;
    background-size:24px 24px !important}
  body.pat-4{background:repeating-linear-gradient(45deg,#f3f6ff,#f3f6ff 14px,#eaf0ff 14px,#eaf0ff 28px) !important}
  body.pat-5{background:
      radial-gradient(ellipse at 20% 20%,#d8f3ee,transparent 55%),
      radial-gradient(ellipse at 82% 28%,#e7dcff,transparent 55%),
      radial-gradient(ellipse at 50% 105%,#ffe7d1,transparent 55%),#f7f7fb !important;
    background-attachment:fixed !important}
  /* ── Dark mode (Claude-style: warm charcoal, soft contrast) ──────────
     The palette is inverted with hue preserved, then softened + warmed so
     surfaces land near Claude's #262624/#30302e charcoals instead of harsh
     blue-blacks. Media (img/canvas/video) re-inverts to stay true-color;
     the residual brightness/sepia leaves it slightly dimmed+warm, which is
     what you want in dark mode anyway. */
  html.theme-dark{color-scheme:dark}
  html.theme-dark body{background:#262624 !important;background-image:none !important}
  html.theme-dark #app{filter:invert(1) hue-rotate(180deg) brightness(.95) contrast(.9) sepia(.12)}
  html.theme-dark #app img,html.theme-dark #app canvas,html.theme-dark #app video,
  html.theme-dark #app .no-invert{filter:invert(1) hue-rotate(180deg)}
  html.theme-dark .theme-pop{filter:invert(1) hue-rotate(180deg)}
  /* Chrome that lives OUTSIDE #app gets real dark styles (no filter) */
  html.theme-dark #pw-overlay{background:
    radial-gradient(ellipse 70% 50% at 50% -10%,rgba(87,80,70,.45),transparent 60%),
    linear-gradient(180deg,#1f1e1d,#262624)}
  html.theme-dark .pw-card{background:#30302e;border-color:#3e3d39;box-shadow:0 20px 60px rgba(0,0,0,.55)}
  html.theme-dark .pw-card h2{color:#f5f4ee}
  html.theme-dark .pw-card p{color:#b8b5ad}
  html.theme-dark .pw-card .inp{background:#262624;border-color:#4a4844;color:#f5f4ee}
  html.theme-dark .fab{border-color:rgba(255,255,255,.18);
    box-shadow:0 8px 24px rgba(0,0,0,.45),inset 0 1px 0 rgba(255,255,255,.16)}
  html.theme-dark .fab-label{background:rgba(48,48,46,.72);color:#f5f4ee;border-color:rgba(255,255,255,.14)}
  html.theme-dark .fab-label::after{border-top-color:rgba(48,48,46,.72)}
  .fab-stack{position:fixed;right:18px;bottom:168px;z-index:650;display:flex;flex-direction:column;gap:10px;align-items:flex-end}
  /* Frosted-glass FABs: translucent tinted fill + backdrop blur + light rim */
  .fab{width:44px;height:44px;border-radius:50%;cursor:pointer;display:grid;place-items:center;
    color:#0369a1;background:linear-gradient(135deg,rgba(14,165,233,.28),rgba(3,105,161,.18));
    border:1px solid rgba(255,255,255,.55);
    backdrop-filter:blur(14px) saturate(1.7);-webkit-backdrop-filter:blur(14px) saturate(1.7);
    box-shadow:0 8px 24px rgba(2,8,23,.16),inset 0 1px 0 rgba(255,255,255,.55),inset 0 -6px 12px rgba(255,255,255,.14);
    transition:transform .15s,background .2s,box-shadow .2s}
  .fab:hover{transform:translateY(-2px);background:linear-gradient(135deg,rgba(14,165,233,.42),rgba(3,105,161,.28));
    box-shadow:0 12px 28px rgba(2,8,23,.2),inset 0 1px 0 rgba(255,255,255,.65)}
  .fab.theme{color:#6d28d9;background:linear-gradient(135deg,rgba(139,92,246,.3),rgba(109,40,217,.18))}
  .fab.theme:hover{background:linear-gradient(135deg,rgba(139,92,246,.44),rgba(109,40,217,.28))}
  .fab.moon{color:#475569;background:linear-gradient(135deg,rgba(148,163,184,.32),rgba(71,85,105,.2))}
  .fab.moon:hover{background:linear-gradient(135deg,rgba(148,163,184,.46),rgba(71,85,105,.3))}
  html.theme-dark .fab.moon{color:#d97757;background:linear-gradient(135deg,rgba(217,119,87,.32),rgba(150,70,45,.22))}
  html.theme-dark .fab.moon:hover{background:linear-gradient(135deg,rgba(217,119,87,.46),rgba(150,70,45,.32))}
  .fab.laser{color:#b91c1c;background:linear-gradient(135deg,rgba(239,68,68,.3),rgba(185,28,28,.18))}
  .fab.laser:hover{background:linear-gradient(135deg,rgba(239,68,68,.44),rgba(185,28,28,.28))}
  .fab.laser.active{box-shadow:0 0 0 3px rgba(239,68,68,.3),0 0 16px 3px rgba(239,68,68,.45),
    0 8px 24px rgba(2,8,23,.16),inset 0 1px 0 rgba(255,255,255,.55)}
  .fab.laser.active svg{animation:laserFabSpin 6s linear infinite}
  @keyframes laserFabSpin{to{transform:rotate(360deg)}}
  .fab-label{align-self:flex-end;background:rgba(255,255,255,.55);color:#b91c1c;
    font:800 11px/1 'Inter',system-ui,sans-serif;padding:5px 11px;border-radius:11px;
    border:1px solid rgba(255,255,255,.65);
    backdrop-filter:blur(12px) saturate(1.6);-webkit-backdrop-filter:blur(12px) saturate(1.6);
    box-shadow:0 5px 14px rgba(185,28,28,.14),inset 0 1px 0 rgba(255,255,255,.6);
    position:relative;pointer-events:none;letter-spacing:.02em;white-space:nowrap;margin-bottom:-2px;
    opacity:0;transform:translateY(4px);transition:opacity .18s,transform .18s}
  .fab-label::after{content:"";position:absolute;right:17px;bottom:-5px;
    border-left:5px solid transparent;border-right:5px solid transparent;border-top:5px solid rgba(255,255,255,.8);transition:border-top-color .18s}
  .fab-stack:hover .fab-label{opacity:1;transform:none}
  body.laser-on .fab-label{opacity:1;transform:none;background:rgba(185,28,28,.78);color:#fff;border-color:rgba(255,255,255,.35)}
  body.laser-on .fab-label::after{border-top-color:rgba(185,28,28,.78)}
  .fab svg{width:20px;height:20px}
  .theme-pop{position:fixed;right:18px;bottom:80px;z-index:601;background:#fff;border:1px solid #e2e8f0;
    border-radius:14px;box-shadow:0 16px 40px rgba(2,8,23,.22);padding:14px;width:240px;display:none}
  .theme-pop.open{display:block}
  .tp-title{font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:#64748b;margin:2px 0 8px}
  .tp-modes{display:flex;gap:8px;margin-bottom:14px}
  .tp-mode{flex:1;border:1.5px solid #e2e8f0;background:#f8fafc;border-radius:10px;padding:9px;cursor:pointer;
    font-weight:700;font-size:13px;color:#0f172a;font-family:inherit}
  .tp-mode.sel{border-color:#8b5cf6;background:#f5f3ff;color:#6d28d9}
  .tp-swatches{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}
  .tp-sw{height:34px;border-radius:9px;border:2px solid transparent;cursor:pointer;outline:1px solid #e2e8f0}
  .tp-sw.sel{border-color:#0ea5e9}
  .sw1{background:linear-gradient(135deg,#eaf2ff,#fff7 ,#eafff2)}
  .sw2{background:#f6f8fc;background-image:radial-gradient(#c7d2fe 1.4px,transparent 1.5px);background-size:8px 8px}
  .sw3{background:#f7faf9;background-image:linear-gradient(#cfe3df 1px,transparent 1px),linear-gradient(90deg,#cfe3df 1px,transparent 1px);background-size:9px 9px}
  .sw4{background:repeating-linear-gradient(45deg,#f3f6ff,#f3f6ff 6px,#dde7ff 6px,#dde7ff 12px)}
  .sw5{background:radial-gradient(circle at 25% 25%,#d8f3ee,transparent 60%),radial-gradient(circle at 80% 70%,#e7dcff,transparent 60%),#fff}
</style>

<div class="fab-stack">
  <button class="fab moon" id="dark-fab" onclick="toggleDarkMode()" title="Dark mode" aria-label="Toggle dark mode">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79z"/></svg>
  </button>
  <div class="fab-label" id="laser-label" aria-hidden="true">Laser</div>
  <button class="fab laser" id="laser-fab" onclick="toggleLaser()" title="Laser pointer — toggle (L)" aria-label="Toggle laser pointer">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="3"/><circle cx="12" cy="12" r="8"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/></svg>
  </button>
  <button class="fab" onclick="fibScrollTop()" title="Scroll to top" aria-label="Scroll to top">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="18 15 12 9 6 15"/></svg>
  </button>
  <button class="fab" onclick="fibScrollBottom()" title="Scroll to bottom" aria-label="Scroll to bottom">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>
  </button>
</div>

<script>
(function(){
  const TYPE = 'First Iraqi Bank';
  function typeBrand(){
    const out = document.getElementById('fib-type-out');
    if (!out) return;
    let i = 0, dir = 1;
    (function step(){
      out.textContent = TYPE.slice(0, i);
      i += dir;
      if (i > TYPE.length){ dir = -1; i = TYPE.length; return setTimeout(step, 2600); }
      if (i < 0){ dir = 1; i = 0; return setTimeout(step, 700); }
      setTimeout(step, dir > 0 ? 95 : 45);
    })();
  }
  window.fibScrollTop    = () => window.scrollTo({top:0, behavior:'smooth'});
  window.fibScrollBottom = () => window.scrollTo({top:document.body.scrollHeight, behavior:'smooth'});
  // ── Dark mode toggle (Claude-style theme, persisted per device) ──
  const MOON_SVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79z"/></svg>';
  const SUN_SVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><line x1="12" y1="2" x2="12" y2="4"/><line x1="12" y1="20" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="6.34" y2="6.34"/><line x1="17.66" y1="17.66" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="4" y2="12"/><line x1="20" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="6.34" y2="17.66"/><line x1="17.66" y1="6.34" x2="19.07" y2="4.93"/></svg>';
  function syncDarkFab(on){
    const b = document.getElementById('dark-fab'); if (!b) return;
    b.innerHTML = on ? SUN_SVG : MOON_SVG;
    b.title = on ? 'Switch to light mode' : 'Switch to dark mode';
  }
  window.toggleDarkMode = function(){
    const on = document.documentElement.classList.toggle('theme-dark');
    try { localStorage.setItem('fibTheme', on ? 'dark' : 'light'); } catch(e){}
    syncDarkFab(on);
  };
  let dark = false;
  try { dark = localStorage.getItem('fibTheme') === 'dark'; } catch(e){}
  if (dark) document.documentElement.classList.add('theme-dark');
  syncDarkFab(dark);
  window.addEventListener('load', () => setTimeout(typeBrand, 400));
})();
</script>
</body>
</html>
"""

# ─────────────────────────────────────────────────────────────────────────────
# admin.html
# ─────────────────────────────────────────────────────────────────────────────
_ADMIN = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin · Progress Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,sans-serif;color:#1e293b;line-height:1.5;
  min-height:100vh;padding:clamp(12px,3vw,40px);
  background:radial-gradient(ellipse 90% 50% at 15% -5%,#bfdbfe88,transparent),
  radial-gradient(ellipse 70% 60% at 95% 15%,#ddd6fe44,transparent),#f0f6ff;
  background-attachment:fixed}
.wrap{max-width:820px;margin:0 auto}
#pw-overlay{position:fixed;inset:0;
  background:linear-gradient(160deg,#dbeafe,#ede9fe90,#f0fdf4);
  backdrop-filter:blur(20px);
  display:flex;align-items:center;justify-content:center;z-index:300}
.pw-card{background:#fff;border:1px solid #e2e8f0;border-radius:22px;
  box-shadow:0 20px 60px rgba(59,130,246,.15);
  padding:42px 50px;width:min(400px,92vw);text-align:center}
.pw-card h2{font-size:22px;font-weight:800;margin-bottom:5px}
.pw-card p{color:#64748b;font-size:13px;margin-bottom:24px}
.inp{width:100%;border:1.5px solid #e2e8f0;border-radius:10px;background:#f8fafc;
  color:#1e293b;font-size:15px;padding:11px 15px;outline:none;font-family:inherit;transition:border .2s}
.inp:focus{border-color:#3b82f6;background:#fff}
.btn-primary{margin-top:11px;width:100%;
  background:linear-gradient(135deg,#3b82f6,#1d4ed8);
  color:#fff;font-weight:700;font-size:14px;border:none;border-radius:10px;
  padding:12px;cursor:pointer;font-family:inherit}
.err-msg{color:#dc2626;font-size:12px;margin-top:9px;min-height:16px}
header{display:flex;align-items:center;justify-content:space-between;
  flex-wrap:wrap;gap:10px;margin-bottom:22px}
h1{font-size:clamp(22px,5vw,30px);font-weight:800;letter-spacing:-.04em}
h1 span{color:#2563eb}
.back{display:inline-flex;align-items:center;gap:5px;background:#fff;
  border:1.5px solid #e2e8f0;border-radius:8px;color:#334155;font-size:12.5px;
  font-weight:600;padding:7px 13px;text-decoration:none;transition:all .15s;
  box-shadow:0 1px 3px rgba(0,0,0,.05)}
.back:hover{background:#f8fafc}
.card{background:#fff;border:1.5px solid #e2e8f0;border-radius:14px;
  padding:20px 22px;margin-bottom:14px;
  box-shadow:0 2px 12px rgba(0,0,0,.05)}
.card-hdr{display:flex;align-items:center;gap:8px;margin-bottom:14px}
.card-hdr h2{font-size:14px;font-weight:700;color:#334155}
.dot{width:7px;height:7px;border-radius:50%;background:#3b82f6;box-shadow:0 0 6px rgba(59,130,246,.5)}
/* token */
.tok-saved-row{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.tok-badge{display:inline-flex;align-items:center;gap:5px;
  background:#dcfce7;border:1px solid #bbf7d0;border-radius:7px;
  color:#166534;font-size:12.5px;font-weight:600;padding:5px 11px}
.lnk{font-size:12px;color:#2563eb;cursor:pointer;background:none;
  border:none;font-family:inherit;font-weight:600;padding:0;text-decoration:underline}
.tok-row{display:flex;gap:7px;align-items:center;margin-top:10px;flex-wrap:wrap}
.tok-inp{flex:1;min-width:200px;border:1.5px solid #e2e8f0;border-radius:8px;
  font-size:12.5px;padding:8px 12px;outline:none;background:#f8fafc;
  color:#1e293b;font-family:'JetBrains Mono',monospace;transition:border .15s}
.tok-inp:focus{border-color:#3b82f6;background:#fff}
.tok-save-btn{background:#3b82f6;color:#fff;border:none;border-radius:8px;
  font-size:12.5px;font-weight:700;padding:9px 16px;cursor:pointer;font-family:inherit;white-space:nowrap}
.hint{font-size:11.5px;color:#64748b;margin-top:7px;line-height:1.6}
.hint a{color:#2563eb}
/* big refresh */
.refresh-wrap{text-align:center;padding:8px 0}
.big-btn{display:inline-flex;align-items:center;gap:9px;
  background:linear-gradient(135deg,#3b82f6,#1d4ed8);
  color:#fff;border:none;border-radius:14px;
  font-size:16px;font-weight:700;padding:15px 36px;
  cursor:pointer;transition:opacity .2s;
  box-shadow:0 4px 20px rgba(59,130,246,.35);font-family:inherit}
.big-btn:hover{opacity:.9}
.big-btn:disabled{opacity:.45;cursor:not-allowed}
#rmsg{margin-top:12px;font-size:12.5px;min-height:18px}
#rmsg.ok{color:#059669}
#rmsg.err{color:#dc2626}
/* runs */
.run-item{border:1.5px solid #e2e8f0;border-radius:10px;
  padding:11px 14px;margin-bottom:7px;cursor:pointer;transition:background .12s}
.run-item:hover{background:#f8fafc}
.run-hd{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.run-name{font-size:13px;font-weight:600;flex:1}
.run-dt{font-family:'JetBrains Mono',monospace;font-size:10.5px;color:#94a3b8}
.sb{font-size:11px;font-weight:700;padding:2px 8px;border-radius:8px;white-space:nowrap}
.sb-ok{background:#dcfce7;color:#166534}
.sb-fail{background:#fee2e2;color:#991b1b}
.sb-run{background:#fef9c3;color:#92400e}
.sb-other{background:#f1f5f9;color:#64748b}
.log-box{display:none;margin-top:9px;background:#0f172a;border-radius:8px;
  padding:12px;overflow:auto;max-height:340px}
.log-box.open{display:block}
.log-box pre{font-family:'JetBrains Mono',monospace;font-size:10.5px;
  color:#94a3b8;line-height:1.65;white-space:pre-wrap;word-break:break-all}
.loading{font-size:12.5px;color:#94a3b8;padding:6px 0}
.reload-lnk{margin-left:auto;background:transparent;border:none;
  color:#3b82f6;font-size:12px;font-weight:600;cursor:pointer;font-family:inherit}

/* Schedule editor */
.sched-slot{flex:1;min-width:140px}
.sched-slot label{font-size:10px;font-weight:700;color:#94a3b8;
  text-transform:uppercase;letter-spacing:.1em;display:block;margin-bottom:5px}
.sched-time{border:1.5px solid #e2e8f0;border-radius:7px;background:#f8fafc;
  font-size:14px;padding:7px 11px;outline:none;font-family:'JetBrains Mono',monospace;
  color:#0f172a;width:100%}
.sched-time:focus{border-color:#3b82f6;background:#fff}
.day-toggles{display:flex;gap:6px;flex-wrap:wrap}
.day-toggles label{display:inline-flex;align-items:center;gap:5px;
  background:#f1f5f9;border:1.5px solid #e2e8f0;border-radius:7px;
  padding:7px 12px;cursor:pointer;font-size:12.5px;font-weight:600;
  color:#475569;transition:all .15s}
.day-toggles label:has(input:checked){background:#dbeafe;border-color:#93c5fd;color:#1d4ed8}
.day-toggles input{accent-color:#2563eb}
</style>
</head>
<body>

<div id="pw-overlay">
  <div class="pw-card">
    <div style="font-size:28px;margin-bottom:10px">⚙️</div>
    <h2>Admin Panel</h2>
    <p>Enter site password to continue</p>
    <input id="pw-inp" class="inp" type="password" placeholder="Password"
           autocomplete="current-password" onkeydown="if(event.key==='Enter')checkPw()">
    <button class="btn-primary" onclick="checkPw()">Unlock →</button>
    <div class="err-msg" id="pw-err"></div>
  </div>
</div>

<div id="app" style="display:none">
<div class="wrap">
  <header>
    <h1>Admin <span>Panel</span></h1>
    <a class="back" href="index.html">← Back to Report</a>
  </header>

  <!-- Weekly report day card -->
  <div class="card">
    <div class="card-hdr">
      <span class="dot"></span>
      <h2>Weekly Report Day</h2>
      <button class="reload-lnk" onclick="loadSchedule()">↻ Reload</button>
    </div>
    <p style="font-size:12.5px;color:#64748b;margin-bottom:14px">
      Pick the day the <strong>weekly snapshot</strong> is captured. GitHub saves the baseline on this day each week.
      The live dashboard keeps refreshing every 10 secondss on its own — this only controls the saved weekly record.
    </p>
    <div id="sched-loading" class="loading">Loading…</div>
    <div id="sched-editor" style="display:none">
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:8px">
        <div style="flex:1;min-width:180px">
          <label style="font-size:12px;font-weight:700;color:#475569;display:block;margin-bottom:8px">WEEKLY BASELINE DAY</label>
          <select id="sched-weekly-day" style="border:1.5px solid #e2e8f0;border-radius:7px;background:#f8fafc;font-size:14px;padding:8px 11px;outline:none;color:#0f172a;width:100%">
            <option value="0">Sunday</option>
            <option value="1">Monday</option>
            <option value="2">Tuesday</option>
            <option value="3" selected>Wednesday</option>
            <option value="4">Thursday</option>
            <option value="5">Friday</option>
            <option value="6">Saturday</option>
          </select>
        </div>
        <div style="flex:1;min-width:150px">
          <label style="font-size:12px;font-weight:700;color:#475569;display:block;margin-bottom:8px">CAPTURE TIME (BAGHDAD)</label>
          <input type="time" id="sched-time" value="14:55" style="border:1.5px solid #e2e8f0;border-radius:7px;background:#f8fafc;font-size:14px;padding:8px 11px;outline:none;color:#0f172a;width:100%;font-family:'JetBrains Mono',monospace">
        </div>
      </div>
      <div class="hint" style="margin-bottom:14px">The snapshot saved on this <b>day &amp; time</b> becomes the <b>weekly baseline</b> that week-over-week changes compare against. GitHub captures it automatically — no need to open the site.</div>
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <button class="tok-save-btn" onclick="saveSchedule()">Save</button>
        <span id="auth-status" style="font-size:11.5px;color:#64748b"></span>
      </div>
      <div id="sched-msg" style="font-size:12.5px;margin-top:10px;min-height:18px"></div>
    </div>
  </div>

  <!-- Recent runs card -->
  <div class="card">
    <div class="card-hdr">
      <span class="dot"></span>
      <h2>Recent Workflow Runs</h2>
      <button class="reload-lnk" onclick="loadRuns()">↻ Reload</button>
    </div>
    <div id="runs"><div class="loading">Loading…</div></div>
  </div>
</div>
</div>

<script>
const ENC_BLOB = __ENC_BLOB__;
const REPO     = "__REPO__";
let GH_PAT = '';

// ── GitHub proxy (optional) — see index template for rationale ──
const GH_PROXY = "__GH_PROXY__".trim();
(function installGitHubProxy(){
  if (!GH_PROXY) return;
  const _origFetch = window.fetch.bind(window);
  const GH = 'https://api.github.com';
  window.fetch = function(url, opts){
    opts = opts || {};
    if (typeof url === 'string' && url.startsWith(GH)) {
      const path = url.slice(GH.length);
      const pw   = sessionStorage.getItem('pw_cache') || '';
      const hdrs = {'Content-Type':'application/json', 'X-Proxy-Auth': pw};
      // Forward the comment password (set transiently by postComments) so the
      // Worker can enforce it server-side for comment operations.
      if (window.__COMMENT_PW) hdrs['X-Comment-Auth'] = window.__COMMENT_PW;
      return _origFetch(GH_PROXY, {
        method: 'POST',
        headers: hdrs,
        body: JSON.stringify({ path, method: (opts.method || 'GET'), ghBody: opts.body || null })
      });
    }
    return _origFetch(url, opts);
  };
})();

function _b64dec(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}
async function _deriveKey(password,salt,iter){
  const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),{name:'PBKDF2'},false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:iter,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['decrypt']);
}
async function decryptBlob(blob,password){
  const key=await _deriveKey(password,_b64dec(blob.salt),blob.iter);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:_b64dec(blob.nonce)},key,_b64dec(blob.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

// The Admin Panel password is NEVER stored in this page. It is verified
// SERVER-SIDE by the Worker proxy (its ADMIN_PASSWORD secret); the dashboard
// password (SITE_PASSWORD) is rejected here so only the admin password opens it.
async function checkPw(){
  const inp=document.getElementById('pw-inp');
  const err=document.getElementById('pw-err');
  const v=inp.value; if(!v) return;
  err.textContent='Checking…';
  const fail=(m)=>{ err.textContent=m||'Incorrect password.'; inp.value=''; inp.focus(); setTimeout(()=>err.textContent='',3000); };
  if (GH_PROXY) {
    // Verify the password server-side. Only the admin role unlocks the panel.
    try{
      const r=await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':v},body:JSON.stringify({action:'verify'})});
      if(r.status!==200) return fail();
      const d=await r.json();
      if(d.role!=='admin') return fail();   // reject the dashboard password
    }catch(e){ return fail('Cannot reach server — try again.'); }
    GH_PAT = v;
    sessionStorage.setItem('pw_cache', v);
    err.textContent=''; unlock();
  } else {
    // Legacy (no proxy): decrypt the embedded PAT blob with SITE_PASSWORD.
    try{
      const data=await decryptBlob(ENC_BLOB,v);
      GH_PAT=data.pat||'';
      sessionStorage.setItem('pw_cache',v);
      if (GH_PAT) localStorage.setItem('gh_token', GH_PAT);
      err.textContent=''; unlock();
    }catch(e){ fail(); }
  }
}
function unlock(){
  document.getElementById('pw-overlay').style.display='none';
  document.getElementById('app').style.display='block';
  loadRuns();
  loadSchedule();
  _updateAuthStatus();
}

function _updateAuthStatus(){
  const el = document.getElementById('auth-status');
  if (!el) return;
  if (GH_PAT) {
    const persisted = !!localStorage.getItem('gh_token');
    el.innerHTML = persisted
      ? '<span style="color:#047857">&#10003; Token saved on this device — schedule edits work without re-entering the password.</span>'
      : '<span style="color:#475569">Token loaded from this session only.</span>';
  } else {
    el.innerHTML = '<span style="color:#dc2626">No token — refresh and re-enter password.</span>';
  }
}

// ── Schedule editor (data/schedule.json) ───────────────────────────────────
const DAYS_LABEL = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
let _SCHED_SHA = null;

function _utcSlotToBaghdadTime(s){
  // s = "HH:MM" UTC → "HH:MM" Baghdad (UTC+3)
  const [h,m] = s.split(':').map(Number);
  const bh = (h + 3) % 24;
  return `${String(bh).padStart(2,'0')}:${String(m).padStart(2,'0')}`;
}
function _baghdadTimeToUtcSlot(t){
  const [bh,bm] = t.split(':').map(Number);
  const h = ((bh - 3) + 24) % 24;
  return `${String(h).padStart(2,'0')}:${String(bm||0).padStart(2,'0')}`;
}

// Preserve the existing capture time across saves (UI no longer edits it).
let _SCHED_SLOTS = ['11:55'];

async function loadSchedule(){
  const editor = document.getElementById('sched-editor');
  const loading = document.getElementById('sched-loading');
  try{
    const headers={'Accept':'application/vnd.github+json'};
    const tok=localStorage.getItem('gh_token')||sessionStorage.getItem('gh_token')||GH_PAT;
    if(tok) headers['Authorization']=`Bearer ${tok}`;
    const refRes=await fetch(`https://api.github.com/repos/${REPO}/commits/main?t=${Date.now()}`,{headers,cache:'no-store'});
    const sha=(await refRes.json()).sha;
    const r=await fetch(`https://api.github.com/repos/${REPO}/contents/data/schedule.json?ref=${sha}`,{headers,cache:'no-store'});
    const j=await r.json();
    _SCHED_SHA=j.sha;
    const cfg=JSON.parse(atob((j.content||'').replace(/\s/g,''))||'{}');
    // Keep whatever capture time is already configured (default one daily slot).
    let slots = cfg.slots_utc;
    if (!slots || !slots.length) slots = (cfg.hours_utc||[]).map(h => `${String(h).padStart(2,'0')}:00`);
    _SCHED_SLOTS = (slots && slots.length) ? slots : ['11:55'];
    const wd = (cfg.weekly_day===undefined||cfg.weekly_day===null) ? 3 : cfg.weekly_day;
    document.getElementById('sched-weekly-day').value=String(wd);
    document.getElementById('sched-time').value = _utcSlotToBaghdadTime(_SCHED_SLOTS[0] || '11:55');
    loading.style.display='none';
    editor.style.display='';
  }catch(e){
    loading.textContent='Failed to load: '+e.message;
    console.warn(e);
  }
}

async function saveSchedule(){
  const tok = GH_PAT || localStorage.getItem('gh_token') || sessionStorage.getItem('gh_token');
  if(!tok){ document.getElementById('sched-msg').innerHTML='<span style="color:#dc2626">Authentication missing — refresh the page and re-enter your password.</span>'; return; }
  const weeklyDay=parseInt(document.getElementById('sched-weekly-day').value);
  const baghdadTime=document.getElementById('sched-time').value || '14:55';
  const slotUtc=_baghdadTimeToUtcSlot(baghdadTime);
  // The weekly snapshot runs ONLY on the baseline day, at the chosen time; no email.
  const cfg={
    slots_utc:  [slotUtc],
    hours_utc:  [parseInt(slotUtc.split(':')[0])],
    active_days: [weeklyDay],
    weekly_day: weeklyDay,
    send_email: false,
    description: `Weekly snapshot on ${DAYS_LABEL[weeklyDay]} at ${baghdadTime} Baghdad`,
  };
  const msg=document.getElementById('sched-msg');
  msg.innerHTML='<span style="color:#64748b">Saving…</span>';
  const content=btoa(unescape(encodeURIComponent(JSON.stringify(cfg, null, 2)+'\n')));
  try{
    const r=await fetch(`https://api.github.com/repos/${REPO}/contents/data/schedule.json`,{
      method:'PUT',
      headers:{'Authorization':`Bearer ${tok}`,'Accept':'application/vnd.github+json','Content-Type':'application/json'},
      body: JSON.stringify({message:`Set weekly report to ${DAYS_LABEL[weeklyDay]} ${baghdadTime} Baghdad`,content,sha:_SCHED_SHA})
    });
    if(r.ok){
      msg.innerHTML = `<div style="background:#dcfce7;border:1px solid #86efac;color:#166534;padding:10px 14px;border-radius:8px;font-weight:600;font-size:13px;margin-top:8px">
        ✓ Saved — weekly snapshot will be captured every <b>${DAYS_LABEL[weeklyDay]}</b> at <b>${baghdadTime}</b> Baghdad, automatically.
      </div>`;
      loadSchedule();
    }else{
      const j=await r.json();
      msg.innerHTML = `<div style="background:#fee2e2;border:1px solid #fca5a5;color:#7f1d1d;padding:10px 14px;border-radius:8px;font-weight:600;font-size:13px;margin-top:8px">
        ✗ Save failed: ${(j.message||r.status)}
      </div>`;
    }
  }catch(e){
    msg.innerHTML = `<div style="background:#fee2e2;border:1px solid #fca5a5;color:#7f1d1d;padding:10px 14px;border-radius:8px;font-weight:600;font-size:13px;margin-top:8px">
      ✗ Network error: ${e.message}
    </div>`;
  }
}
document.addEventListener('DOMContentLoaded', () => {
  // Require the password on every page load (including refresh): clear any
  // cached credential so the gate is always shown until the user re-enters it.
  sessionStorage.removeItem('pw_cache');
  localStorage.removeItem('gh_token');
});

async function loadRuns(){
  const el=document.getElementById('runs');
  el.innerHTML='<div class="loading">Loading…</div>';
  try{
    const h={'Accept':'application/vnd.github+json'};
    if(GH_PAT) h['Authorization']=`Bearer ${GH_PAT}`;
    const r=await fetch(`https://api.github.com/repos/${REPO}/actions/runs?per_page=10`,{headers:h});
    const d=await r.json();
    const runs=d.workflow_runs||[];
    if(!runs.length){el.innerHTML='<div class="loading">No runs found.</div>';return;}
    el.innerHTML=runs.map(run=>{
      const sc=run.conclusion==='success'?'sb-ok':run.conclusion==='failure'?'sb-fail':run.status==='in_progress'?'sb-run':'sb-other';
      const icon=run.event==='schedule'?'⏰':run.event==='workflow_dispatch'?'🖱':'▶';
      const dt=new Date(run.created_at).toLocaleString();
      return `<div class="run-item" onclick="toggleLog(${run.id})">
        <div class="run-hd">
          <span class="run-name">${icon} ${esc(run.display_title||run.name||'Run')}</span>
          <span class="sb ${sc}">${run.conclusion||run.status}</span>
          <span class="run-dt">${dt}</span>
        </div>
        <div id="log-${run.id}" class="log-box"><pre id="lp-${run.id}">Click to expand…</pre></div>
      </div>`;
    }).join('');
  }catch(e){el.innerHTML=`<div class="loading" style="color:#dc2626">Failed: ${esc(e.message)}</div>`;}
}

async function toggleLog(rid){
  const box=document.getElementById('log-'+rid);
  const pre=document.getElementById('lp-'+rid);
  box.classList.toggle('open');
  if(!box.classList.contains('open')||pre.dataset.loaded)return;
  pre.textContent='Fetching logs…';
  const h={'Accept':'application/vnd.github+json'};
  if(GH_PAT) h['Authorization']=`Bearer ${GH_PAT}`;
  try{
    const jr=await fetch(`https://api.github.com/repos/${REPO}/actions/runs/${rid}/jobs`,{headers:h});
    const jd=await jr.json();
    const job=(jd.jobs||[])[0];
    if(!job){pre.textContent='No jobs found.';pre.dataset.loaded='1';return;}
    const lr=await fetch(`https://api.github.com/repos/${REPO}/actions/jobs/${job.id}/logs`,{headers:h});
    pre.textContent=lr.status===200?await lr.text()
      :(job.steps||[]).map(s=>`${s.conclusion==='success'?'✓':'✗'} ${s.name}  [${s.conclusion||s.status}]`).join('\n')||'Log unavailable (requires auth token).';
    pre.dataset.loaded='1';
  }catch(e){pre.textContent='Error: '+e.message;}
}

const esc = s => { const d=document.createElement('div'); d.textContent=s; return d.innerHTML; };
</script>
</body>
</html>
"""

# ─────────────────────────────────────────────────────────────────────────────
def build(report, analysis, hidden_people=None):
    pw_hash  = os.environ.get("SITE_PASSWORD_HASH", "")
    password = os.environ.get("SITE_PASSWORD", "")
    gh_pat   = os.environ.get("GH_PAT", "")
    delete_hash = os.environ.get("DELETE_PASSWORD_HASH", "")
    repo     = os.environ.get("GITHUB_REPOSITORY",
                              "rudawathegw-design/jira-weekly-progress")

    if not password:
        raise RuntimeError("SITE_PASSWORD env var is required to encrypt the payload.")

    # If a GitHub-proxy Worker URL is configured, the PAT lives in the Worker
    # (off the public page). We then embed an EMPTY pat and the proxy URL, and
    # the dashboard routes all GitHub calls through the Worker, authenticating
    # with the site password. Until GH_PROXY_URL is set, behaviour is unchanged
    # (PAT embedded encrypted, calls go straight to GitHub).
    proxy_url   = os.environ.get("GH_PROXY_URL", "").strip()
    # SECURITY — fail closed: the GitHub PAT must NEVER be embedded in the public
    # pages (even encrypted: a cracked password would then yield a code-pushing
    # token). The Worker proxy holds it server-side. If the proxy URL is missing
    # AND a PAT is present, ABORT the build loudly rather than silently leaking
    # the PAT into public HTML. The PAT is never embedded under any path.
    if not proxy_url and gh_pat:
        raise RuntimeError(
            "Refusing to embed the GitHub PAT in the public site. Set GH_PROXY_URL "
            "(the Cloudflare Worker URL) so the PAT stays server-side."
        )
    embedded_pat = ""   # never embedded — all GitHub calls go through the Worker

    # Encrypt the entire sensitive payload as a single blob
    payload = json.dumps({
        "report":   report,
        "analysis": analysis,
        "pat":      embedded_pat,
        "hidden":   list(hidden_people or []),
    }, ensure_ascii=False, default=str)
    enc_blob = encrypt_payload(payload, password)
    enc_blob_json = json.dumps(enc_blob)

    index = (_INDEX
             .replace("__REPO__",     repo)
             .replace("__ENC_BLOB__", enc_blob_json)
             .replace("__DELETE_HASH__", delete_hash)
             .replace("__GH_PROXY__",  proxy_url)
             .replace("__DATE__",     report.get("date", "")))

    # Admin gets a smaller encrypted blob containing only the PAT
    admin_blob = encrypt_payload(json.dumps({"pat": embedded_pat}), password)
    admin = (_ADMIN
             .replace("__ENC_BLOB__", json.dumps(admin_blob))
             .replace("__GH_PROXY__",  proxy_url)
             .replace("__REPO__",     repo))

    os.makedirs(DOCS_DIR, exist_ok=True)
    with open(os.path.join(DOCS_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(index)
    with open(os.path.join(DOCS_DIR, "admin.html"), "w", encoding="utf-8") as f:
        f.write(admin)
    print("Wrote docs/index.html and docs/admin.html")
