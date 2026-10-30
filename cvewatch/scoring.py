"""Decide the alert tier of an item. P1 = alert now, P2 = include in digest, None = ignore.

P1 needs evidence of exploitation (CISA KEV, VulnCheck KEV, public exploit, high EPSS). A high
CVSS alone goes to the digest: vendors publish in batches (Patch Tuesday, Oracle CPU) and
alerting on score would flood the channel with dozens of messages in one run.
"""
from .model import exploit_signal

TIER_RANK = {None: 0, "P2": 1, "P1": 2}


def is_critical(item, cfg):
    """Watchlist CVE with a critical score but no exploitation evidence yet (🟠 in the digest)."""
    score = item["cvss"]["score"] if item["cvss"] else 0
    return bool(item.get("watch_groups")) and score >= cfg["tiers"]["p2"]["watchlist_critical_cvss"] and not exploit_signal(item)


def classify(item, cfg, kev_recent, vulncheck_recent=False):
    """Return (tier, reasons). `*_recent` is True when the CVE was added to that KEV list recently."""
    p1, p2 = cfg["tiers"]["p1"], cfg["tiers"]["p2"]
    score = item["cvss"]["score"] if item["cvss"] else None
    epss = item["epss"][0] if item["epss"] else None
    watched = bool(item.get("watch_groups"))
    new_cisa = bool(item["kev"]) and kev_recent
    new_vulncheck = bool(item.get("vulncheck")) and vulncheck_recent
    reasons = []

    if new_cisa and p1.get("kev_new", True):
        reasons.append("Mới vào CISA KEV: đang bị khai thác thực tế")
    if watched:
        if new_vulncheck and not new_cisa and p1.get("vulncheck_kev_watchlist", True):
            reasons.append("Thuộc watchlist, VulnCheck ghi nhận đang bị khai thác")
        if epss is not None and epss >= p1["watchlist_min_epss"]:
            reasons.append(f"Thuộc watchlist, EPSS {epss:.2f}")
        if (not reasons and p1.get("watchlist_exploit", True) and exploit_signal(item)
                and score is not None and score >= p1["watchlist_exploit_min_cvss"]):
            reasons.append(f"Thuộc watchlist, CVSS {score}, đã có exploit công khai")
    if reasons:
        return "P1", reasons

    if new_vulncheck and p2.get("vulncheck_kev_new", True):
        return "P2", ["VulnCheck ghi nhận đang bị khai thác"]
    if watched and score is not None:
        if score >= p2["watchlist_critical_cvss"]:
            return "P2", [f"Thuộc watchlist, CVSS {score}: nghiêm trọng, chưa có dấu hiệu khai thác"]
        if score >= p2["watchlist_min_cvss"]:
            return "P2", [f"Thuộc watchlist, CVSS {score}"]
    if score is not None:
        network_ok = not p2.get("global_require_network", True) or item["attack_vector"] == "Network"
        if score >= p2["global_min_cvss"] and network_ok:
            return "P2", [f"CVSS {score}, tấn công qua mạng"]
        if exploit_signal(item) and score >= p2["global_exploit_min_cvss"]:
            return "P2", [f"CVSS {score}, đã có exploit công khai"]
    return None, []


def priority_key(item):
    """Sort key, most urgent first."""
    score = item["cvss"]["score"] if item["cvss"] else 0.0
    epss = item["epss"][0] if item["epss"] else 0.0
    return (-(item["kev"] is not None), -bool(item.get("vulncheck")), -exploit_signal(item),
            -bool(item.get("watch_groups")), -score, -epss, item["id"])
