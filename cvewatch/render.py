"""Markdown (repo) and HTML (Telegram) rendering."""
import html
import os
import re

from .model import exploit_signal

NO_FIX = "Chưa có thông tin bản vá trong dữ liệu nguồn, theo dõi advisory của hãng."
NO_LLM = "_Tóm tắt tiếng Việt chưa có (LLM không khả dụng ở lần chạy này). Dưới đây là mô tả gốc._"


def product_label(item):
    if item["kev"]:
        return f"{item['kev']['vendor']} {item['kev']['product']}".strip()
    for a in item["affected"]:
        label = f"{a['vendor']} {a['product']}".strip()
        if label and label.lower() not in ("n/a n/a", "n/a"):
            return label
    return "Không rõ"


def cvss_label(item):
    c = item["cvss"]
    return f"{c['score']} (v{c['version']})" if c else "chưa có"


def epss_label(item):
    e = item["epss"]
    return f"{e[0]:.3f} (top {100 - e[1] * 100:.1f}%)" if e else "chưa có"


def exploit_label(item):
    parts = []
    if item["kev"]:
        parts.append("CISA KEV")
    if item["public_exploit"]:
        parts.append("nuclei template")
    if item["ssvc_exploitation"] in ("poc", "active"):
        parts.append(f"SSVC: {item['ssvc_exploitation']}")
    return ", ".join(parts) or "chưa ghi nhận"


def _md_escape(text):
    return text.replace("|", "\\|").replace("\n", " ")


def _bullets(lines):
    return "\n".join(f"- {line}" for line in lines) if lines else ""


def _detail_md(state, level):
    """Body sections shared by alerts and digest entries. `level` is the heading depth."""
    item, s = state["item"], state.get("summary")
    h = "#" * level
    out = []
    if s:
        out += [f"{h} Tóm tắt", s["summary"], "", f"{h} Cách tấn công", s["attack"], "",
                f"**Điều kiện khai thác:** {s['prerequisites']}", "", f"**Ảnh hưởng:** {s['impact']}", "",
                f"{h} Khắc phục", _bullets(s["remediation"]) or NO_FIX, ""]
        if s["workaround"]:
            out += [f"{h} Giảm thiểu tạm thời", _bullets(s["workaround"]), ""]
    else:
        out += [NO_LLM, "", f"{h} Mô tả gốc", item["description"] or item["title"], "", f"{h} Khắc phục"]
        out += [f"Áp dụng bản vá hoặc hướng dẫn giảm thiểu của hãng, xem mục Tham khảo. CISA yêu cầu xử lý trước {item['kev']['due_date']}."
                if item["kev"] else NO_FIX, ""]
    if item["kev"]:
        out += [f"**CISA KEV:** thêm ngày {item['kev']['date_added']}, hạn xử lý {item['kev']['due_date']}, "
                f"ransomware: {item['kev']['ransomware']}", ""]
    versions = [f"{a['vendor']} {a['product']}: {'; '.join(a['versions'])}" for a in item["affected"] if a["versions"]]
    if versions:
        out += [f"{h} Phiên bản", _bullets(versions[:8]), ""]
    if item["ghsa"]:
        fixes = [f"{g['ecosystem']} `{g['package']}`: bị ảnh hưởng `{g['vulnerable']}`, bản vá `{g['patched'] or 'chưa có'}`"
                 for g in item["ghsa"][:8]]
        out += [f"{h} Bản vá theo package (GitHub Advisory)", _bullets(fixes), ""]
    if item["references"]:
        out += [f"{h} Tham khảo", _bullets(item["references"]), ""]
    return out


def _facts_table(state, tz_now_label):
    item = state["item"]
    rows = [
        ("Mức cảnh báo", f"{state['tier']}: {'; '.join(state['reasons'])}"),
        ("Sản phẩm", product_label(item)),
        ("CVSS", f"{cvss_label(item)} `{item['cvss']['vector']}`" if item["cvss"] else "chưa có"),
        ("Attack vector", item["attack_vector"] or "chưa rõ"),
        ("EPSS", epss_label(item)),
        ("Khai thác", exploit_label(item)),
        ("CWE", ", ".join(item["cwes"]) or "chưa rõ"),
        ("Công bố", item["published"] or "chưa rõ"),
        ("Bot ghi nhận", tz_now_label),
    ]
    return ["| | |", "|---|---|"] + [f"| {k} | {_md_escape(str(v))} |" for k, v in rows]


def alert_markdown(state, now_label):
    item = state["item"]
    out = [f"# 🔴 {item['id']}: {item['title'] or product_label(item)}", ""]
    out += _facts_table(state, now_label) + [""]
    out += _detail_md(state, 2)
    return "\n".join(out).rstrip() + "\n"


def digest_markdown(states, title, summarized_ids):
    kev = [s for s in states if s["item"]["kev"]]
    watched = [s for s in states if not s["item"]["kev"] and s["item"].get("watch_groups")]
    other = [s for s in states if not s["item"]["kev"] and not s["item"].get("watch_groups")]
    out = [f"# {title}", "",
           f"Tổng **{len(states)}** CVE: {len(kev)} đang bị khai thác (KEV), {len(watched)} thuộc watchlist (ngoài KEV), "
           f"{len(other)} nghiêm trọng khác.", "",
           "| CVE | Mức | Sản phẩm | CVSS | EPSS | Khai thác | Nhóm |", "|---|---|---|---|---|---|---|"]
    for s in states:
        i = s["item"]
        epss = f"{i['epss'][0]:.2f}" if i["epss"] else "-"
        out.append(f"| [{i['id']}](#{i['id'].lower()}) | {s['tier']} | {_md_escape(product_label(i))} | "
                   f"{i['cvss']['score'] if i['cvss'] else '-'} | {epss} | "
                   f"{exploit_label(i) if exploit_signal(i) else '-'} | {_md_escape(', '.join(i.get('watch_groups') or [])) or '-'} |")
    out.append("")
    for heading, group in (("Đang bị khai thác (CISA KEV)", kev), ("Thuộc watchlist", watched), ("Nghiêm trọng khác", other)):
        if not group:
            continue
        out += [f"## {heading}", ""]
        for s in group:
            i = s["item"]
            out += [f"### {i['id']}", f"**{i['title'] or product_label(i)}**", "",
                     f"{product_label(i)} · CVSS {cvss_label(i)} · EPSS {epss_label(i)} · Khai thác: {exploit_label(i)}"
                     f" · Lý do: {'; '.join(s['reasons'])}", ""]
            if i["id"] in summarized_ids or s.get("summary"):
                out += _detail_md(s, 4)
            else:
                desc = i["description"] or i["title"]
                out += [desc[:400] + ("…" if len(desc) > 400 else ""), ""]
                if i["references"]:
                    out += [f"Tham khảo: {i['references'][0]}", ""]
    return "\n".join(out).rstrip() + "\n"


def _h(text):
    return html.escape(text or "", quote=False)


def telegram_alert(state, url):
    item, s = state["item"], state.get("summary")
    lines = [
        f"🔴 <b>{state['tier']} · {_h(item['id'])}</b>",
        f"<b>{_h(item['title'] or product_label(item))}</b>",
        f"Sản phẩm: {_h(product_label(item))}",
        f"CVSS {_h(cvss_label(item))} · EPSS {_h(epss_label(item))} · Khai thác: {_h(exploit_label(item))}",
        f"Lý do: {_h('; '.join(state['reasons']))}",
        "",
    ]
    if s:
        lines += [f"<b>Tóm tắt:</b> {_h(s['summary'])}", f"<b>Tấn công:</b> {_h(s['attack'])}",
                  f"<b>Điều kiện:</b> {_h(s['prerequisites'])}", "<b>Khắc phục:</b>"]
        lines += [f"• {_h(x)}" for x in (s["remediation"] or [NO_FIX])]
        if s["workaround"]:
            lines += ["<b>Giảm thiểu tạm thời:</b>"] + [f"• {_h(x)}" for x in s["workaround"]]
    else:
        desc = re.sub(r"\s+", " ", item["description"] or "").strip()
        lines += [_h(desc[:600] + ("…" if len(desc) > 600 else ""))]
        if item["kev"]:
            lines += [f"<b>CISA KEV:</b> hạn xử lý {_h(item['kev']['due_date'])}, ransomware: {_h(item['kev']['ransomware'])}"]
    if url:
        lines += ["", f'<a href="{_h(url)}">Chi tiết</a>']
    return "\n".join(lines)


def telegram_digest(states, title, url, limit=15):
    kev = sum(1 for s in states if s["item"]["kev"])
    watched = sum(1 for s in states if s["item"].get("watch_groups"))
    lines = [f"📰 <b>{_h(title)}</b>", f"{len(states)} CVE · {kev} KEV · {watched} watchlist", ""]
    for s in states[:limit]:
        i = s["item"]
        tag = " 🔥" if exploit_signal(i) else ""
        score = i["cvss"]["score"] if i["cvss"] else "-"
        lines.append(f"• <b>{_h(i['id'])}</b> {_h(product_label(i))} · CVSS {score}{tag}")
    if len(states) > limit:
        lines.append(f"… và {len(states) - limit} CVE khác")
    if url:
        lines += ["", f'<a href="{_h(url)}">Xem bản tin đầy đủ</a>']
    return "\n".join(lines)


README_START = "<!-- AUTO:START -->"
README_END = "<!-- AUTO:END -->"


def _list_md(root, sub, limit):
    found = []
    base = os.path.join(root, sub)
    for dirpath, _, files in os.walk(base):
        for f in files:
            if f.endswith(".md"):
                found.append(os.path.relpath(os.path.join(dirpath, f), root))
    return sorted(found, reverse=True)[:limit]


def update_readme(root):
    path = os.path.join(root, "README.md")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    reports = _list_md(root, "reports", 14)
    # Alert files are named YYYY-MM-DD_HHMM_CVE-ID.md, so sorting by file name is chronological.
    alerts = sorted(_list_md(root, "alerts", 10000), key=os.path.basename, reverse=True)[:15]
    block = [README_START, "", "### Bản tin gần nhất", ""]
    block += [f"- [{p.removeprefix('reports/').removesuffix('.md')}]({p})" for p in reports] or ["_Chưa có._"]
    block += ["", "### Cảnh báo P1 gần nhất", ""]
    for p in alerts:
        with open(os.path.join(root, p), encoding="utf-8") as f:
            heading = f.readline().lstrip("# ").strip()
        block.append(f"- [{heading}]({p})")
    if not alerts:
        block.append("_Chưa có._")
    block += ["", README_END]
    new = "\n".join(block)
    if README_START in text and README_END in text:
        text = re.sub(re.escape(README_START) + ".*?" + re.escape(README_END), lambda _: new, text, flags=re.S)
    else:
        text = text.rstrip() + "\n\n" + new + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
