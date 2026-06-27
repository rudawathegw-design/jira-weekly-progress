"""
render_image.py — server-side PNG render of the progress report using Pillow.
Output: docs/report.png (also written to a fixed path for email attachment).
"""
import os
from PIL import Image, ImageDraw, ImageFont

OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "docs", "report.png")


# ── font helpers ────────────────────────────────────────────────────────────
def _font(size=14, bold=False):
    """Pick a system font available on Ubuntu runner; fallback to default."""
    candidates_bold = [
        "/usr/share/fonts/truetype/dejavu/DejaVu-Sans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "DejaVuSans-Bold.ttf",
        "arial.ttf",
    ]
    candidates_reg = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "DejaVuSans.ttf",
        "arial.ttf",
    ]
    for p in (candidates_bold if bold else candidates_reg):
        try:
            return ImageFont.truetype(p, size)
        except (OSError, IOError):
            continue
    return ImageFont.load_default()


def _text(draw, xy, text, font, color, anchor="la"):
    """Draw text with anchor support (PIL Pillow 9+)."""
    try:
        draw.text(xy, text, font=font, fill=color, anchor=anchor)
    except (TypeError, ValueError):
        draw.text(xy, text, font=font, fill=color)


def _measure(draw, text, font):
    try:
        bbox = draw.textbbox((0, 0), text, font=font)
        return bbox[2] - bbox[0], bbox[3] - bbox[1]
    except AttributeError:
        return font.getsize(text)


def _rounded_rect(draw, xy, radius, fill=None, outline=None, width=1):
    """PIL >=8.2 supports rounded_rectangle natively."""
    try:
        draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline, width=width)
    except AttributeError:
        draw.rectangle(xy, fill=fill, outline=outline)


# ── main render ─────────────────────────────────────────────────────────────
def render(report, analysis):
    rows = report.get("rows", [])
    date = report.get("date", "")
    last_date = report.get("last_snap_date") or "—"
    team_pct = report.get("team_total", 0)
    last_pct = report.get("team_last_week")
    delta = report.get("team_delta")
    grand_total = report.get("grand_total", 0)
    grand_done = report.get("grand_done", 0)
    total_overdue = sum(r.get("overdue", 0) or 0 for r in rows)

    # layout
    PAD = 48
    WIDTH = 1480
    ROW_H = 44
    HDR_H = 52
    TITLE_H = 110

    # 11 columns (Owner + 7 numeric + Done% + LastWk + Δ)
    COL_W = [260, 75, 75, 95, 80, 90, 85, 110, 95, 100]
    TBL_W = sum(COL_W)

    # Pre-compute total height
    risks = [r for r in (analysis.get("risks") or []) if isinstance(r, dict) and r.get("name")]
    summary = analysis.get("summary", "")
    summary_lines = _wrap(summary, max_chars=170)
    summary_h = 24 + len(summary_lines) * 22 + 16
    ai_section_h = summary_h + (30 + len(risks) * 50 if risks else 0) + 16
    stats_h = 110
    table_h = 56 + HDR_H + (len(rows) + 1) * ROW_H  # +banner
    total_h = TITLE_H + stats_h + 50 + ai_section_h + 50 + table_h + PAD * 2

    # ── canvas ──
    img = Image.new("RGB", (WIDTH, total_h), "#f0f6ff")
    d = ImageDraw.Draw(img)

    # background gradient (approximated with 3 bands)
    for y in range(0, total_h, 4):
        ratio = y / total_h
        r = int(219 + (240 - 219) * ratio)
        g = int(234 + (246 - 234) * ratio)
        b = int(254 + (255 - 254) * ratio)
        d.rectangle([0, y, WIDTH, y + 4], fill=(r, g, b))

    f_title = _font(34, bold=True)
    f_sub = _font(14)
    f_h2 = _font(15, bold=True)
    f_lbl = _font(11, bold=True)
    f_lbl_lg = _font(13, bold=True)
    f_val_lg = _font(30, bold=True)
    f_val = _font(22, bold=True)
    f_th = _font(13, bold=True)
    f_td = _font(14)
    f_td_b = _font(14, bold=True)
    f_mono = _font(14)
    f_mono_b = _font(15, bold=True)
    f_summary = _font(16)
    f_risk_name = _font(15, bold=True)
    f_risk = _font(13)

    y = PAD

    # ── Title block ──
    _text(d, (PAD, y), "FIBTMP Progress Report", f_title, "#0f172a")
    # Last-updated badge top-right
    badge_text = date
    bw, bh = _measure(d, badge_text, f_mono_b)
    badge_w = bw + 130
    badge_x = WIDTH - PAD - badge_w
    _rounded_rect(d, [badge_x, y + 6, badge_x + badge_w, y + 56], 12,
                  fill="#dbeafe", outline="#93c5fd", width=2)
    _text(d, (badge_x + 18, y + 18), "LAST UPDATED", f_lbl, "#1e40af")
    _text(d, (badge_x + 18, y + 36), badge_text, f_mono_b, "#0f172a")

    _text(d, (PAD, y + 50), "Project Management Office",
          f_sub, "#64748b")
    y += TITLE_H

    # ── Stats cards row ──
    stats = [
        ("This Period", f"{team_pct}%",
         "#059669" if (delta or 0) > 0 else "#dc2626" if (delta or 0) < 0 else "#1e293b"),
        ("Last Period", f"{last_pct}%" if last_pct is not None else "—", "#64748b"),
        ("Change",
         f"{'+' if (delta or 0) > 0 else ''}{delta}%" if delta is not None else "—",
         "#059669" if (delta or 0) > 0 else "#dc2626" if (delta or 0) < 0 else "#64748b"),
        ("Members", str(len(rows)), "#2563eb"),
        ("Total Tasks", str(grand_total), "#334155"),
        ("Done", str(grand_done), "#059669"),
        ("Overdue", str(total_overdue), "#dc2626"),
    ]
    sw = (WIDTH - PAD * 2 - (len(stats) - 1) * 8) // len(stats)
    for i, (lbl, val, col) in enumerate(stats):
        sx = PAD + i * (sw + 8)
        _rounded_rect(d, [sx, y, sx + sw, y + 80], 12, fill="#ffffff", outline="#e2e8f0", width=2)
        _text(d, (sx + 14, y + 14), lbl.upper(), f_lbl, "#94a3b8")
        _text(d, (sx + 14, y + 36), val, f_val_lg, col)
    y += stats_h

    # ── AI summary section ──
    _text(d, (PAD, y), "🤖 AI ANALYSIS", f_h2, "#2563eb")
    y += 28
    _rounded_rect(d, [PAD, y, WIDTH - PAD, y + summary_h], 12,
                  fill="#ffffff", outline="#bfdbfe", width=2)
    for i, line in enumerate(summary_lines):
        _text(d, (PAD + 18, y + 14 + i * 22), line, f_summary, "#334155")
    y += summary_h + 14

    # Risk cards (2 columns)
    if risks:
        _text(d, (PAD, y), f"⚠ RISK FLAGS ({len(risks)})", f_h2, "#b45309")
        y += 26
        col_w = (WIDTH - PAD * 2 - 12) // 2
        for i, rk in enumerate(risks):
            cx = PAD + (i % 2) * (col_w + 12)
            cy = y + (i // 2) * 52
            _rounded_rect(d, [cx, cy, cx + col_w, cy + 46], 10,
                          fill="#fffbeb", outline="#fde68a", width=2)
            _text(d, (cx + 14, cy + 8), "⚠ " + rk["name"], f_risk_name, "#92400e")
            note = (rk.get("note") or "")[:120]
            _text(d, (cx + 14, cy + 28), note, f_risk, "#78350f")
        rows_count = (len(risks) + 1) // 2
        y += rows_count * 52
    y += 20

    # ── Main table with big centered date banner ──
    tx = (WIDTH - TBL_W) // 2 if TBL_W < WIDTH - PAD * 2 else PAD

    # Big date banner (like Excel-style header in user's reference image)
    banner_h = 56
    _rounded_rect(d, [tx, y, tx + TBL_W, y + banner_h], 0,
                  fill="#fafbfc", outline="#cbd5e1", width=2)
    _text(d, (tx + 24, y + banner_h // 2), "THIS WEEK", f_lbl_lg, "#475569", anchor="lm")
    pretty_date = _pretty_date(date)
    _text(d, (tx + TBL_W // 2, y + banner_h // 2), pretty_date,
          _font(26, bold=True), "#0f172a", anchor="mm")
    _text(d, (tx + TBL_W - 24, y + banner_h // 2),
          "vs " + _pretty_date(last_date), f_sub, "#94a3b8", anchor="rm")
    y += banner_h

    # Column header row
    _rounded_rect(d, [tx, y, tx + TBL_W, y + HDR_H], 0, fill="#e8eef5", outline="#cbd5e1", width=2)
    heads = ["Owner", "Total", "Open", "In Prog", "WFA", "Overdue", "Done", "Done %", "Last Wk", "Change"]
    cx = tx
    for i, h in enumerate(heads):
        align = "lm" if i == 0 else "mm"
        ty = y + HDR_H // 2
        xpos = cx + 14 if i == 0 else cx + COL_W[i] // 2
        _text(d, (xpos, ty), h.upper(), f_th, "#475569", anchor=align)
        cx += COL_W[i]
    y += HDR_H

    # Data rows + TOTAL
    data_with_total = list(rows) + [None]
    for ri, r in enumerate(data_with_total):
        is_total = r is None
        if is_total:
            r = {
                "owner": "TOTAL",
                "total": sum(x.get("total", 0) or 0 for x in rows),
                "open": sum(x.get("open", 0) or 0 for x in rows),
                "in_progress": sum(x.get("in_progress", 0) or 0 for x in rows),
                "waiting_for_approval": sum(x.get("waiting_for_approval", 0) or 0 for x in rows),
                "overdue": total_overdue,
                "completed": sum(x.get("completed", 0) or 0 for x in rows),
                "this_week": team_pct,
                "last_week": last_pct,
                "delta": delta,
            }

        d_val = r.get("delta")
        tw = r.get("this_week", 0) or 0
        is_new = d_val is None

        bg = "#ffffff" if ri % 2 == 0 else "#f8fafc"
        if not is_total:
            if not is_new and d_val > 0:
                bg = "#f0fdf4"
            elif not is_new and (d_val < 0 or (d_val == 0 and tw < 100)):
                bg = "#fff5f5"
        if is_total:
            bg = "#fef9c3"   # bright yellow TOTAL row

        d.rectangle([tx, y, tx + TBL_W, y + ROW_H],
                    fill=bg,
                    outline=("#fde047" if is_total else "#e2e8f0"),
                    width=(2 if is_total else 1))

        cx = tx
        # Owner
        name = r["owner"]
        if len(name) > 28:
            name = name[:26] + "…"
        _text(d, (cx + 14, y + ROW_H // 2),
              name, f_td_b if is_total else f_td, "#0f172a", anchor="lm")
        cx += COL_W[0]

        # Numeric columns
        numeric_vals = [
            r.get("total", 0) or 0,
            r.get("open", 0) or 0,
            r.get("in_progress", 0) or 0,
            r.get("waiting_for_approval", 0) or 0,
            r.get("overdue", 0) or 0,
            r.get("completed", 0) or 0,
        ]
        for i, v in enumerate(numeric_vals):
            idx = i + 1
            if i == 4 and v > 0:  # Overdue: red badge, NUMBER ONLY (no emoji)
                badge_text = str(v)
                bw, _ = _measure(d, badge_text, f_td_b)
                bx = cx + COL_W[idx] // 2 - bw // 2 - 10
                _rounded_rect(d, [bx, y + ROW_H // 2 - 12, bx + bw + 20, y + ROW_H // 2 + 12],
                              6, fill="#fee2e2", outline="#fecaca", width=1)
                _text(d, (cx + COL_W[idx] // 2, y + ROW_H // 2), badge_text, f_td_b, "#991b1b", anchor="mm")
            else:
                # All numbers black including zeros — no more washed-out gray
                color = "#0f172a"
                font = f_td_b if i in (0, 5) else f_mono
                _text(d, (cx + COL_W[idx] // 2, y + ROW_H // 2),
                      str(v), font, color, anchor="mm")
            cx += COL_W[idx]

        # Done % column with mini bar
        pct_col = "#2563eb" if is_new or is_total else (
            "#059669" if d_val > 0 else "#dc2626" if d_val < 0 or (d_val == 0 and tw < 100) else "#334155")
        _text(d, (cx + COL_W[7] // 2, y + ROW_H // 2 - 8),
              f"{tw}%", f_mono_b, pct_col, anchor="mm")
        bar_x = cx + 14
        bar_y = y + ROW_H - 13
        bar_w = COL_W[7] - 28
        d.rectangle([bar_x, bar_y, bar_x + bar_w, bar_y + 5], fill="#e2e8f0")
        fill_w = int(bar_w * min(100, tw) / 100)
        d.rectangle([bar_x, bar_y, bar_x + fill_w, bar_y + 5], fill=pct_col)
        cx += COL_W[7]

        # Last Week
        lw_txt = f"{r.get('last_week')}%" if r.get("last_week") is not None else "—"
        _text(d, (cx + COL_W[8] // 2, y + ROW_H // 2),
              lw_txt, f_mono, "#64748b", anchor="mm")
        cx += COL_W[8]

        # Delta badge
        if is_new:
            dt_txt, dt_fg, dt_bg = "NEW", "#92400e", "#fef9c3"
        elif d_val > 0:
            dt_txt, dt_fg, dt_bg = f"+{d_val}%", "#166534", "#dcfce7"
        elif d_val < 0:
            dt_txt, dt_fg, dt_bg = f"{d_val}%", "#991b1b", "#fee2e2"
        else:
            if tw >= 100:
                dt_txt, dt_fg, dt_bg = "±0%", "#64748b", "#f1f5f9"
            else:
                dt_txt, dt_fg, dt_bg = "±0%", "#991b1b", "#fee2e2"
        bw, _ = _measure(d, dt_txt, f_mono_b)
        bx = cx + COL_W[9] // 2 - bw // 2 - 9
        _rounded_rect(d, [bx, y + ROW_H // 2 - 12, bx + bw + 18, y + ROW_H // 2 + 12],
                      8, fill=dt_bg, outline=dt_bg, width=1)
        _text(d, (cx + COL_W[9] // 2, y + ROW_H // 2),
              dt_txt, f_mono_b, dt_fg, anchor="mm")
        y += ROW_H

    # Footer
    y += 20
    _text(d, (PAD, y),
          f"Generated {date} · FIBTMP PMO · {len(rows)} members · {grand_total} tasks · {total_overdue} overdue",
          _font(12), "#94a3b8")

    # Save
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    img.save(OUT_PATH, "PNG", optimize=True)
    print(f"Wrote {OUT_PATH}  ({img.size[0]}x{img.size[1]} px)")
    return OUT_PATH


def _pretty_date(iso):
    if not iso or iso == "—":
        return "—"
    try:
        y, m, dd = str(iso)[:10].split("-")
        months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
        return f"{int(dd)} {months[int(m)-1]} {y}"
    except (ValueError, IndexError):
        return str(iso)


def _wrap(text, max_chars=170):
    """Simple character-based wrapping."""
    words = (text or "").split()
    lines, line = [], ""
    for w in words:
        if len(line) + len(w) + 1 > max_chars and line:
            lines.append(line)
            line = w
        else:
            line = (line + " " + w) if line else w
    if line:
        lines.append(line)
    return lines or [""]
