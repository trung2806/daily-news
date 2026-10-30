import os

import yaml

from cvewatch import model
from cvewatch.scoring import classify
from cvewatch.watchlist import Watchlist

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = yaml.safe_load(open(os.path.join(ROOT, "config", "settings.yml"), encoding="utf-8"))
WL = Watchlist.load(os.path.join(ROOT, "config", "watchlist.yml"))


def record(vendor, product, score=None, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", title="", desc="x", adp=None):
    cna = {
        "title": title,
        "descriptions": [{"lang": "en", "value": desc}],
        "affected": [{"vendor": vendor, "product": product,
                      "versions": [{"status": "affected", "version": "1.0", "lessThan": "1.2"}]}],
        "references": [{"url": "https://example.com/advisory"}],
    }
    if score is not None:
        cna["metrics"] = [{"cvssV3_1": {"baseScore": score, "vectorString": vector, "baseSeverity": "HIGH"}}]
    containers = {"cna": cna}
    if adp:
        containers["adp"] = adp
    return {"cveMetadata": {"cveId": "CVE-2026-0001", "state": "PUBLISHED", "datePublished": "2026-10-30T00:00:00Z"},
            "containers": containers}


def item_of(rec):
    item = model.from_record(rec)
    item["watch_groups"] = WL.match(item)
    return item


def test_watchlist_matches_requested_products():
    assert WL.match(model.from_record(record("Apache Software Foundation", "Apache Tomcat")))
    assert WL.match(model.from_record(record("SAP_SE", "SAP HANA Database")))
    assert WL.match(model.from_record(record("SAP_SE", "SAP Business One")))
    assert WL.match(model.from_record(record("Oracle", "Oracle WebLogic Server")))
    assert WL.match(model.from_record(record("PHP Group", "PHP")))
    assert WL.match(model.from_record(record("Microsoft", "Windows Server 2022", title="Windows Hyper-V RCE")))
    assert WL.match(model.from_record(record("Fortinet", "FortiOS")))


def test_watchlist_avoids_obvious_false_positives():
    assert not WL.match(model.from_record(record("phpmyadmin", "phpMyAdmin")))
    assert not WL.match(model.from_record(record("SAP_SE", "SAP NetWeaver")))
    assert not WL.match(model.from_record(record("acme", "widget", desc="A PHP based CMS")))


def test_tiers():
    assert classify(item_of(record("Fortinet", "FortiOS", 9.8)), CFG, False)[0] == "P1"
    assert classify(item_of(record("Fortinet", "FortiOS", 7.5)), CFG, False)[0] == "P2"
    assert classify(item_of(record("Fortinet", "FortiOS", 5.0)), CFG, False)[0] is None
    assert classify(item_of(record("acme", "widget", 9.8)), CFG, False)[0] == "P2"
    local = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert classify(item_of(record("acme", "widget", 9.3, vector=local)), CFG, False)[0] is None
    assert classify(item_of(record("acme", "widget", 7.0)), CFG, False)[0] is None


def test_kev_and_exploit_signals():
    item = item_of(record("acme", "widget", 6.0))
    item["kev"] = {"vendor": "acme", "product": "widget"}
    assert classify(item, CFG, True)[0] == "P1"
    assert classify(item, CFG, False)[0] is None

    adp = [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [
        {"other": {"type": "ssvc", "content": {"options": [{"Exploitation": "poc"}, {"Automatable": "yes"}]}}},
        {"cvssV3_1": {"baseScore": 8.1, "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}]
    item = item_of(record("Apache", "Apache Tomcat", adp=adp))
    assert item["cvss"]["score"] == 8.1 and item["ssvc_exploitation"] == "poc"
    assert classify(item, CFG, False)[0] == "P1"


def test_rejected_record_is_skipped():
    rec = record("acme", "widget", 9.8)
    rec["cveMetadata"]["state"] = "REJECTED"
    assert model.from_record(rec) is None


def test_record_url_buckets():
    from cvewatch.sources import record_url
    assert record_url("CVE-2026-74912").endswith("/cves/2026/74xxx/CVE-2026-74912.json")
    assert record_url("CVE-2026-1234").endswith("/cves/2026/1xxx/CVE-2026-1234.json")
    assert record_url("CVE-2026-115943").endswith("/cves/2026/115xxx/CVE-2026-115943.json")
