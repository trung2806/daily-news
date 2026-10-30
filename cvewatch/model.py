"""Normalize CVE JSON 5 records and KEV entries into one flat item dict."""

CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
MAX_REFS = 10
MAX_VERSIONS = 12


def _en(descriptions):
    for d in descriptions or []:
        if d.get("lang", "").lower().startswith("en"):
            return d.get("value", "").strip()
    return (descriptions or [{}])[0].get("value", "").strip() if descriptions else ""


def _cvss_from_metrics(metrics, source):
    found = []
    for m in metrics or []:
        for key in CVSS_KEYS:
            if key in m and m[key].get("baseScore") is not None:
                c = m[key]
                found.append({
                    "score": float(c["baseScore"]),
                    "version": key.replace("cvssV", "").replace("_", "."),
                    "vector": c.get("vectorString", ""),
                    "severity": c.get("baseSeverity", ""),
                    "source": source,
                })
    return found


def _ssvc(metrics):
    for m in metrics or []:
        other = m.get("other") or {}
        if other.get("type") == "ssvc":
            opts = {}
            for opt in (other.get("content") or {}).get("options", []):
                opts.update(opt)
            return opts
    return {}


def _versions(affected):
    out = []
    for v in affected.get("versions") or []:
        status = v.get("status")
        ver = v.get("version", "")
        if v.get("lessThan"):
            text = f"{ver} → < {v['lessThan']}" if ver not in ("", "0", "*") else f"< {v['lessThan']}"
        elif v.get("lessThanOrEqual"):
            text = f"{ver} → <= {v['lessThanOrEqual']}" if ver not in ("", "0", "*") else f"<= {v['lessThanOrEqual']}"
        else:
            text = ver
        out.append(f"{status}: {text}")
    return out[:MAX_VERSIONS]


def attack_vector(vector):
    for part in (vector or "").split("/"):
        if part.startswith("AV:"):
            return {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}.get(part[3:], part[3:])
    return ""


def from_record(rec):
    """Return a normalized item, or None for rejected/unparseable records."""
    meta = rec.get("cveMetadata") or {}
    if meta.get("state") != "PUBLISHED":
        return None
    containers = rec.get("containers") or {}
    cna = containers.get("cna") or {}
    adps = containers.get("adp") or []

    cvss = _cvss_from_metrics(cna.get("metrics"), meta.get("assignerShortName") or "CNA")
    ssvc = {}
    for adp in adps:
        src = (adp.get("providerMetadata") or {}).get("shortName") or adp.get("title") or "ADP"
        cvss += _cvss_from_metrics(adp.get("metrics"), src)
        ssvc = ssvc or _ssvc(adp.get("metrics"))
    best = max(cvss, key=lambda c: (c["score"], c["version"] != "2.0")) if cvss else None

    affected = []
    for a in cna.get("affected") or []:
        affected.append({
            "vendor": a.get("vendor") or "",
            "product": a.get("product") or a.get("packageName") or "",
            "versions": _versions(a),
        })

    cwes = []
    for pt in cna.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            label = d.get("cweId") or d.get("description")
            if label and label not in cwes:
                cwes.append(label)

    refs = [r["url"] for r in cna.get("references") or [] if r.get("url")]

    return {
        "id": meta["cveId"],
        "title": (cna.get("title") or "").strip(),
        "description": _en(cna.get("descriptions")),
        "published": meta.get("datePublished"),
        "assigner": meta.get("assignerShortName"),
        "affected": affected[:20],
        "cwes": cwes[:5],
        "cvss": best,
        "attack_vector": attack_vector(best["vector"]) if best else "",
        "ssvc_exploitation": (ssvc.get("Exploitation") or "").lower(),
        "references": refs[:MAX_REFS],
        "kev": None,
        "vulncheck": None,
        "public_exploit": False,
        "epss": None,
        "ghsa": [],
    }


def from_kev(entry, cve_id=None):
    """Minimal item for a CISA or VulnCheck KEV entry whose CVE record could not be fetched."""
    return {
        "id": cve_id or entry["cveID"],
        "title": entry.get("vulnerabilityName", ""),
        "description": entry.get("shortDescription", ""),
        "published": None,
        "assigner": None,
        "affected": [{"vendor": entry.get("vendorProject", ""), "product": entry.get("product", ""), "versions": []}],
        "cwes": entry.get("cwes") or [],
        "cvss": None,
        "attack_vector": "",
        "ssvc_exploitation": "",
        "references": [],
        "kev": None,
        "vulncheck": None,
        "public_exploit": False,
        "epss": None,
        "ghsa": [],
    }


def kev_facts(entry):
    return {
        "date_added": entry.get("dateAdded"),
        "due_date": entry.get("dueDate"),
        "required_action": entry.get("requiredAction"),
        "ransomware": entry.get("knownRansomwareCampaignUse"),
        "notes": entry.get("notes"),
        "vendor": entry.get("vendorProject"),
        "product": entry.get("product"),
    }


def vulncheck_facts(entry):
    return {
        "date_added": (entry.get("date_added") or "")[:10],
        "in_cisa_kev": bool(entry.get("cisa_date_added")),
        "ransomware": entry.get("knownRansomwareCampaignUse"),
        "reported": [r["url"] for r in entry.get("vulncheck_reported_exploitation") or [] if r.get("url")][:5],
        "exploits": [x.get("exploit_type") or "exploit" for x in entry.get("vulncheck_xdb") or []][:5],
    }


def exploit_signal(item):
    return bool(item["kev"] or item.get("vulncheck") or item["public_exploit"]
                or item["ssvc_exploitation"] in ("poc", "active"))
