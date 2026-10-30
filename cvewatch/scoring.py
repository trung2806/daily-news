"""Decide the alert tier of an item. P1 = alert now, P2 = include in digest, None = ignore."""
from .model import exploit_signal

TIER_RANK = {None: 0, "P2": 1, "P1": 2}


def classify(item, cfg, kev_recent):
    """Return (tier, reasons). `kev_recent` is True when the CVE was added to KEV recently."""
    p1, p2 = cfg["tiers"]["p1"], cfg["tiers"]["p2"]
    score = item["cvss"]["score"] if item["cvss"] else None
    epss = item["epss"][0] if item["epss"] else None
    watched = bool(item.get("watch_groups"))
    exploit = exploit_signal(item)
    reasons = []

    if item["kev"] and kev_recent and p1.get("kev_new", True):
        reasons.append("Mới vào CISA KEV: đang bị khai thác thực tế")
    if watched:
        if score is not None and score >= p1["watchlist_min_cvss"]:
            reasons.append(f"Thuộc watchlist, CVSS {score}")
        if epss is not None and epss >= p1["watchlist_min_epss"]:
            reasons.append(f"Thuộc watchlist, EPSS {epss:.2f}")
        if exploit and p1.get("watchlist_public_exploit", True) and not (item["kev"] and kev_recent):
            reasons.append("Thuộc watchlist, đã có exploit công khai")
    if reasons:
        return "P1", reasons

    if watched and score is not None and score >= p2["watchlist_min_cvss"]:
        return "P2", [f"Thuộc watchlist, CVSS {score}"]
    if score is not None:
        network_ok = not p2.get("global_require_network", True) or item["attack_vector"] == "Network"
        if score >= p2["global_min_cvss"] and network_ok:
            return "P2", [f"CVSS {score}, tấn công qua mạng"]
        if exploit and score >= p2["global_exploit_min_cvss"]:
            return "P2", [f"CVSS {score}, đã có exploit công khai"]
    return None, []


def priority_key(item):
    """Sort key, most urgent first."""
    score = item["cvss"]["score"] if item["cvss"] else 0.0
    epss = item["epss"][0] if item["epss"] else 0.0
    return (-(item["kev"] is not None), -exploit_signal(item), -bool(item.get("watch_groups")), -score, -epss, item["id"])
