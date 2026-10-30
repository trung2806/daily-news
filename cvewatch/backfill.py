"""Patch backlog: every CISA KEV entry on the watchlist, plus recent watchlist CVEs.

Writes backlog/patch-backlog.md as a checklist. Items ticked `- [x]` in the existing file stay
ticked when the backlog is regenerated, so the team can track patching in the file itself.
"""
import logging
import os
import re

from . import model, render, sources, summarize
from .model import exploit_signal
from .scoring import priority_key

log = logging.getLogger(__name__)

BACKLOG = "backlog/patch-backlog.md"
_TICKED = re.compile(r"^- \[[xX]\] \*\*(CVE-\d{4}-\d+)\*\*", re.M)
MAX_DESC = 300


def ticked_ids(path):
    try:
        with open(path, encoding="utf-8") as f:
            return set(_TICKED.findall(f.read()))
    except FileNotFoundError:
        return set()


def _clip(text, n=MAX_DESC):
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:n] + ("…" if len(text) > n else "")


def kev_items(ctx, kev, exploit_ids):
    items = []
    for entry in kev.values():
        item = model.from_kev(entry)
        item["kev"] = model.kev_facts(entry)
        item["public_exploit"] = item["id"] in exploit_ids
        item["watch_groups"] = ctx.watchlist.match(item)
        if item["watch_groups"]:
            items.append(item)
    return items


def recent_items(ctx, kev, exploit_ids):
    cfg = ctx.cfg["backfill"]
    changes, _ = sources.fetch_delta(None, cfg["days"] * 24)
    ids = sorted(cid for cid, kind in changes.items() if kind == "new" and cid not in kev)
    log.info("backfill: fetching %d CVE records from the last %d days", len(ids), cfg["days"])
    records = sources.fetch_records(ids, cfg["fetch_workers"])
    items = []
    for cid in ids:
        item = model.from_record(records[cid]) if records.get(cid) else None
        if not item or not item["cvss"]:
            continue
        item["public_exploit"] = cid in exploit_ids
        score = item["cvss"]["score"]
        if score < cfg["min_cvss"] and not (exploit_signal(item) and score >= cfg["exploit_min_cvss"]):
            continue
        item["watch_groups"] = ctx.watchlist.match(item)
        if item["watch_groups"]:
            items.append(item)
    return items


def _kev_line(item, done):
    k = item["kev"]
    flags = []
    if k["ransomware"] == "Known":
        flags.append("🔥 ransomware")
    if item["public_exploit"]:
        flags.append("nuclei template")
    line = (f"- [{'x' if done else ' '}] **{item['id']}** {item['title']} · {k['product']} · thêm KEV {k['date_added']}"
            f" · hạn CISA {k['due_date']}" + (f" · {', '.join(flags)}" if flags else "")
            + f" · [NVD](https://nvd.nist.gov/vuln/detail/{item['id']})")
    return [line, f"  > {_clip(item['description'])}"]


def _recent_lines(item, done):
    s = item.get("summary")
    line = (f"- [{'x' if done else ' '}] **{item['id']}** {item['title'] or render.product_label(item)}"
            f" · {render.product_label(item)} · CVSS {render.cvss_label(item)} · EPSS {render.epss_label(item)}"
            f" · Khai thác: {render.exploit_label(item)}")
    out = [line]
    if s:
        out.append(f"  > {_clip(s['summary'], 500)}")
        out += [f"  > - Khắc phục: {x}" for x in (s["remediation"] or [render.NO_FIX])]
    else:
        out.append(f"  > {_clip(item['description'])}")
    if item["references"]:
        out.append(f"  > Tham khảo: {item['references'][0]}")
    return out


def _by_group(ctx, items):
    """{group label: items}, in watchlist order."""
    groups = {g["label"]: [] for g in ctx.watchlist.groups.values()}
    for item in items:
        groups[item["watch_groups"][0]].append(item)
    return {label: group for label, group in groups.items() if group}


def render_backlog(ctx, kev_list, recent, done):
    days = ctx.cfg["backfill"]["days"]
    total = len(kev_list) + len(recent)
    n_done = sum(1 for i in kev_list + recent if i["id"] in done)
    out = [
        "# Danh sách cần vá (patch backlog)", "",
        f"Cập nhật {ctx.now_label()}. Tổng **{total}** CVE, đã vá **{n_done}**.", "",
        "- **Phần 1:** toàn bộ CVE trong CISA KEV (đã bị khai thác thực tế) thuộc watchlist, không giới hạn thời gian.",
        f"- **Phần 2:** CVE thuộc watchlist công bố trong {days} ngày gần nhất, chưa vào KEV, CVSS ≥ {ctx.cfg['backfill']['min_cvss']}"
        f" (hoặc CVSS ≥ {ctx.cfg['backfill']['exploit_min_cvss']} nếu đã có exploit).", "",
        "Đây là danh sách *có thể* ảnh hưởng tới các hãng trong watchlist. Cần đối chiếu với phiên bản đang chạy thực tế. "
        "Vá xong thì sửa `- [ ]` thành `- [x]` (sửa trực tiếp trên GitHub được). Lần chạy backfill sau sẽ giữ nguyên các dòng đã tick.", "",
        f"## Phần 1: Đang bị khai thác (CISA KEV), {len(kev_list)} CVE", "",
    ]
    for label, items in _by_group(ctx, kev_list).items():
        out += [f"### {label} ({len(items)})", ""]
        # KEV spells product names inconsistently ("Confluence Server and Data Center" vs "Confluence"),
        # so group by vendor and keep the product on each line.
        vendors = {}
        for item in items:
            vendors.setdefault(item["kev"]["vendor"], []).append(item)
        for vendor in sorted(vendors, key=lambda v: (-len(vendors[v]), v)):
            group = sorted(vendors[vendor], key=lambda i: i["kev"]["date_added"], reverse=True)
            out += [f"#### {vendor} ({len(group)})", ""]
            for item in group:
                out += _kev_line(item, item["id"] in done)
            out.append("")
    out += [f"## Phần 2: CVE watchlist {days} ngày gần nhất, {len(recent)} CVE", ""]
    if not recent:
        out += ["_Không có._", ""]
    for label, items in _by_group(ctx, recent).items():
        out += [f"### {label} ({len(items)})", ""]
        for item in items:
            out += _recent_lines(item, item["id"] in done)
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def run(ctx):
    path = os.path.join(ctx.root, BACKLOG)
    done = ticked_ids(path)
    kev = sources.fetch_kev()
    exploit_ids = sources.fetch_nuclei_ids()

    kev_list = kev_items(ctx, kev, exploit_ids)
    recent = recent_items(ctx, kev, exploit_ids)
    epss = sources.fetch_epss([i["id"] for i in recent])
    for item in recent:
        item["epss"] = epss.get(item["id"])
    recent.sort(key=priority_key)

    # LLM only for the recent part; KEV entries already carry a vetted CISA description.
    todo = [i for i in recent if i["id"] not in done][: ctx.cfg["backfill"]["max_summarized"]]
    summaries = summarize.summarize(todo, ctx.cfg, ctx.cfg["llm"]["digest_model"])
    for item in recent:
        item["summary"] = summaries.get(item["id"])

    ctx.write(BACKLOG, render_backlog(ctx, kev_list, recent, done))
    log.info("backlog: %d KEV + %d recent, %d ticked -> %s", len(kev_list), len(recent), len(done), BACKLOG)
