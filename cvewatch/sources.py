"""Fetchers for upstream vulnerability data. Each returns plain dicts/sets."""
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from . import http

log = logging.getLogger(__name__)

CVELIST_DELTA_LOG = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
CVELIST_RECORD = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/{cve}.json"
KEV_URLS = [
    # Official CISA mirror on GitHub; cisa.gov is the fallback.
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
]
NUCLEI_CVES = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
EPSS_API = "https://api.first.org/data/v1/epss"
GHSA_API = "https://api.github.com/advisories"
VULNCHECK_KEV = "https://api.vulncheck.com/v3/index/vulncheck-kev"


def parse_ts(value):
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def fetch_delta(since, first_run_hours):
    """Return ({cve_id: "new"|"updated"}, newest_fetch_time_iso) for cvelistV5 changes after `since`."""
    entries = http.get_json(CVELIST_DELTA_LOG, timeout=120)
    if since:
        cutoff = parse_ts(since)
    else:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=first_run_hours)
    changes = {}
    newest = since
    # deltaLog is newest first; iterate oldest first so "new" wins over a later "updated".
    for entry in reversed(entries):
        fetched = parse_ts(entry["fetchTime"])
        if fetched <= cutoff:
            continue
        for kind in ("new", "updated"):
            for change in entry.get(kind, []):
                changes.setdefault(change["cveId"], kind)
        if newest is None or fetched > parse_ts(newest):
            newest = entry["fetchTime"]
    return changes, newest


def record_url(cve_id):
    _, year, num = cve_id.split("-")
    return CVELIST_RECORD.format(year=year, bucket=num[:-3] or "0", cve=cve_id)


def fetch_record(cve_id):
    try:
        return http.get_json(record_url(cve_id), timeout=30, retries=2)
    except Exception as exc:  # missing or not yet propagated
        log.warning("record %s: %s", cve_id, exc)
        return None


def fetch_records(cve_ids, workers):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(zip(cve_ids, pool.map(fetch_record, cve_ids)))


def fetch_kev():
    for url in KEV_URLS:
        try:
            data = http.get_json(url, timeout=60)
            return {v["cveID"]: v for v in data["vulnerabilities"]}
        except Exception as exc:
            log.warning("KEV %s: %s", url, exc)
    raise RuntimeError("Could not fetch CISA KEV from any source")


def fetch_nuclei_ids():
    """CVE IDs with a public nuclei detection template (signal that exploitation is easy)."""
    try:
        text = http.get(NUCLEI_CVES, timeout=60).text
    except Exception as exc:
        log.warning("nuclei: %s", exc)
        return set()
    ids = set()
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                ids.add(json.loads(line)["ID"])
            except (ValueError, KeyError):
                continue
    return ids


def fetch_epss(cve_ids):
    """Return {cve_id: (epss, percentile)}. New CVEs usually have no score until the next day."""
    out = {}
    ids = sorted(cve_ids)
    for i in range(0, len(ids), 100):
        try:
            data = http.get_json(EPSS_API, params={"cve": ",".join(ids[i:i + 100])}, timeout=30)
        except Exception as exc:
            log.warning("EPSS: %s", exc)
            return out
        for row in data.get("data", []):
            out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    return out


def fetch_ghsa(cve_id):
    """Package-level fix facts from the GitHub Advisory Database, if any."""
    token = os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        advisories = http.get_json(GHSA_API, params={"cve_id": cve_id}, headers=headers, timeout=30, retries=2)
    except Exception as exc:
        log.debug("GHSA %s: %s", cve_id, exc)
        return []
    facts = []
    for adv in advisories:
        for vuln in adv.get("vulnerabilities") or []:
            pkg = vuln.get("package") or {}
            facts.append({
                "ghsa_id": adv.get("ghsa_id"),
                "ecosystem": pkg.get("ecosystem"),
                "package": pkg.get("name"),
                "vulnerable": vuln.get("vulnerable_version_range"),
                "patched": vuln.get("first_patched_version"),
            })
    return facts


def fetch_vulncheck_kev(pages=3):
    """Newest VulnCheck KEV entries as {cve_id: entry}. Empty when VULNCHECK_API_TOKEN is not set.

    VulnCheck KEV lists CVEs with public evidence of exploitation (vendor reports, threat intel,
    news), usually earlier and wider than CISA KEV. Each entry links to that evidence.
    """
    token = os.environ.get("VULNCHECK_API_TOKEN")
    if not token:
        log.info("VulnCheck KEV: VULNCHECK_API_TOKEN not set, skipping")
        return {}
    # Docs show "Bearer <token>"; the generated SDK sends the bare token. Try both.
    auth_values = [f"Bearer {token}", token]
    out = {}
    for page in range(1, pages + 1):
        params = {"sort": "date_added", "order": "desc", "limit": 100, "page": page}
        rows = None
        while auth_values:
            try:
                data = http.get_json(VULNCHECK_KEV, params=params, timeout=60, retries=2,
                                     headers={"Authorization": auth_values[0], "Accept": "application/json"})
                rows = data.get("data") or []
                break
            except Exception as exc:
                status = getattr(getattr(exc, "response", None), "status_code", None)
                if status == 401 and len(auth_values) > 1:
                    auth_values.pop(0)
                    continue
                log.warning("VulnCheck KEV: %s %s", status or "", type(exc).__name__)
                return out
        if rows is None:
            return out
        for entry in rows:
            for cve_id in entry.get("cve") or []:
                out.setdefault(cve_id, entry)
        if len(rows) < 100:
            break
    newest = max((e.get("date_added") or "" for e in out.values()), default="")
    log.info("VulnCheck KEV: %d entries, newest added %s", len(out), newest[:10] or "?")
    return out
