"""Entry point.

    python -m cvewatch run      # poll sources, alert P1, publish the digest when a slot is due
    python -m cvewatch digest   # publish the digest now
    python -m cvewatch backfill # rebuild backlog/patch-backlog.md
"""
import argparse
import glob
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import yaml

from . import backfill, model, notify, render, sources, summarize
from .scoring import TIER_RANK, classify, priority_key
from .store import Store
from .watchlist import Watchlist

log = logging.getLogger("cvewatch")


class Ctx:
    def __init__(self, args):
        self.root = os.path.abspath(args.root)
        with open(os.path.join(self.root, "config", "settings.yml"), encoding="utf-8") as f:
            self.cfg = yaml.safe_load(f)
        self.watchlist = Watchlist.load(os.path.join(self.root, "config", "watchlist.yml"))
        self.store = Store(os.path.abspath(args.data))
        self.dry_run = args.dry_run
        self.tz = ZoneInfo(self.cfg.get("timezone", "Asia/Ho_Chi_Minh"))
        self.now = datetime.now(timezone.utc)
        self.local_now = self.now.astimezone(self.tz)
        self.changed_main = False

    def now_label(self):
        return self.local_now.strftime("%H:%M %d/%m/%Y")

    def github_url(self, rel_path):
        repo = os.environ.get("GITHUB_REPOSITORY")
        if not repo:
            return None
        server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        return f"{server}/{repo}/blob/{os.environ.get('GITHUB_REF_NAME', 'main')}/{rel_path}"

    def write(self, rel_path, text):
        path = os.path.join(self.root, rel_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        self.changed_main = True


def new_state(ctx, item):
    return {"item": item, "tier": None, "reasons": [], "first_seen": ctx.now.isoformat(), "updated": ctx.now.isoformat(),
            "alerted_at": None, "kev_alerted": False, "digested_at": None, "summary": None}


def enrich_ghsa(items, workers):
    todo = [i for i in items if not i["ghsa"]]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for item, facts in zip(todo, pool.map(lambda i: sources.fetch_ghsa(i["id"]), todo)):
            item["ghsa"] = facts


def process(ctx, items, kev_recent):
    """Classify items, persist the ones worth tracking and send P1 alerts."""
    cfg = ctx.cfg
    track_days = cfg["retention"]["track_unscored_days"]
    alerts, kept = [], []
    for item in items:
        prev = ctx.store.get(item["id"])
        tier, reasons = classify(item, cfg, item["id"] in kev_recent)
        published = sources.parse_ts(item["published"]) if item["published"] else ctx.now
        watch_unscored = item["watch_groups"] and item["cvss"] is None and ctx.now - published < timedelta(days=track_days)
        if not tier and not watch_unscored and not prev:
            continue
        state = prev or new_state(ctx, item)
        # Keep what was already computed for this CVE across refetches.
        item["ghsa"] = item["ghsa"] or state["item"].get("ghsa", [])
        if item["epss"] is None:
            item["epss"] = state["item"].get("epss")
        state["item"], state["updated"] = item, ctx.now.isoformat()
        if TIER_RANK[tier] >= TIER_RANK[state["tier"]]:
            state["tier"], state["reasons"] = tier, reasons
        new_kev = bool(item["kev"]) and item["id"] in kev_recent and not state["kev_alerted"]
        if state["tier"] == "P1" and (state["alerted_at"] is None or new_kev):
            alerts.append(state)
        kept.append(state)

    enrich_ghsa([s["item"] for s in kept if s["tier"]], cfg["poll"]["fetch_workers"])

    alerts.sort(key=lambda s: priority_key(s["item"]))
    need = [s["item"] for s in alerts if not s["summary"]][: cfg["llm"]["max_p1_per_run"]]
    summaries = summarize.summarize(need, cfg, cfg["llm"]["p1_model"])
    for state in alerts:
        state["summary"] = state["summary"] or summaries.get(state["item"]["id"])
        stamp = ctx.local_now.strftime("%Y-%m-%d_%H%M")
        rel = f"alerts/{ctx.local_now:%Y/%m}/{stamp}_{state['item']['id']}.md"
        ctx.write(rel, render.alert_markdown(state, ctx.now_label()))
        note = None if state["summary"] else summarize.last_error
        notify.telegram(render.telegram_alert(state, ctx.github_url(rel), note), cfg, ctx.dry_run)
        state["alerted_at"] = ctx.now.isoformat()
        state["kev_alerted"] = state["kev_alerted"] or bool(state["item"]["kev"])
    for state in kept:
        ctx.store.put(state)
    log.info("tracked %d, alerted %d", len(kept), len(alerts))


def poll(ctx, cursor):
    cfg = ctx.cfg["poll"]
    changes, newest = sources.fetch_delta(cursor.get("delta_fetch_time"), cfg["first_run_lookback_hours"])
    tracked = ctx.store.tracked_ids()
    kev = sources.fetch_kev()
    since = ctx.local_now.date() - timedelta(days=cfg["kev_recent_days"])
    kev_recent = {cid for cid, e in kev.items() if date.fromisoformat(e["dateAdded"]) >= since}

    ids = {cid for cid, kind in changes.items() if kind == "new" or cid in tracked}
    for cid in kev_recent:
        state = ctx.store.get(cid)
        if not state or not state["kev_alerted"]:
            ids.add(cid)
    log.info("delta: %d changes, %d to evaluate (%d recent KEV)", len(changes), len(ids), len(kev_recent))

    records = sources.fetch_records(sorted(ids), cfg["fetch_workers"])
    exploit_ids = sources.fetch_nuclei_ids()
    items = []
    for cid in sorted(ids):
        item = model.from_record(records[cid]) if records.get(cid) else None
        if item is None and cid in kev:
            item = model.from_kev(kev[cid])
        if item is None:
            continue
        if cid in kev:
            item["kev"] = model.kev_facts(kev[cid])
        item["public_exploit"] = cid in exploit_ids
        item["watch_groups"] = ctx.watchlist.match(item)
        items.append(item)

    relevant = [i["id"] for i in items if i["watch_groups"] or i["kev"] or (i["cvss"] and i["cvss"]["score"] >= 7)]
    epss = sources.fetch_epss(relevant)
    for item in items:
        item["epss"] = epss.get(item["id"])

    process(ctx, items, kev_recent)
    cursor["delta_fetch_time"] = newest


def followup(ctx):
    """Send the Vietnamese analysis for recent P1 alerts that went out without one (e.g. bad token)."""
    if summarize.last_error or not summarize.available(ctx.cfg):
        return
    since = ctx.now - timedelta(hours=ctx.cfg["llm"].get("followup_hours", 72))
    pending = [s for s in ctx.store.all()
               if s["tier"] == "P1" and s["alerted_at"] and not s["summary"] and sources.parse_ts(s["alerted_at"]) >= since]
    if not pending:
        return
    pending.sort(key=lambda s: priority_key(s["item"]))
    pending = pending[: ctx.cfg["llm"]["max_p1_per_run"]]
    summaries = summarize.summarize([s["item"] for s in pending], ctx.cfg, ctx.cfg["llm"]["p1_model"])
    for state in pending:
        state["summary"] = summaries.get(state["item"]["id"])
        if not state["summary"]:
            continue
        # Rewrite the original alert file in place so the repo link shows the analysis too.
        files = sorted(glob.glob(os.path.join(ctx.root, "alerts", "**", f"*_{state['item']['id']}.md"), recursive=True))
        rel = os.path.relpath(files[-1], ctx.root) if files else (
            f"alerts/{ctx.local_now:%Y/%m}/{ctx.local_now:%Y-%m-%d_%H%M}_{state['item']['id']}.md")
        ctx.write(rel, render.alert_markdown(state, ctx.now_label()))
        notify.telegram(render.telegram_alert(state, ctx.github_url(rel), followup=True), ctx.cfg, ctx.dry_run)
        ctx.store.put(state)
    log.info("followup: sent analysis for %d/%d alerts", sum(1 for s in pending if s["summary"]), len(pending))


def refresh_tracked(ctx):
    """Daily EPSS refresh for tracked CVEs below P1; a jump in EPSS can escalate to an alert."""
    states = [s for s in ctx.store.all() if s["tier"] != "P1"]
    if not states:
        return
    epss = sources.fetch_epss([s["item"]["id"] for s in states])
    items = []
    for s in states:
        s["item"]["epss"] = epss.get(s["item"]["id"], s["item"]["epss"])
        s["item"]["watch_groups"] = ctx.watchlist.match(s["item"])
        items.append(s["item"])
    process(ctx, items, set())


def current_slot(ctx):
    """Latest digest time at or before now, as a local datetime."""
    times = sorted(ctx.cfg["digest"]["times"])
    today = ctx.local_now.date()
    candidates = []
    for day in (today - timedelta(days=1), today):
        for t in times:
            h, m = map(int, t.split(":"))
            candidates.append(datetime(day.year, day.month, day.day, h, m, tzinfo=ctx.tz))
    return max(c for c in candidates if c <= ctx.local_now)


def digest(ctx, slot):
    cfg = ctx.cfg["digest"]
    states = [s for s in ctx.store.all() if s["tier"] and not s["digested_at"]]
    if not states:
        log.info("digest %s: nothing new", slot)
        return
    epss = sources.fetch_epss([s["item"]["id"] for s in states])
    for s in states:
        s["item"]["epss"] = epss.get(s["item"]["id"], s["item"]["epss"])
    states.sort(key=lambda s: priority_key(s["item"]))
    shown, overflow = states[: cfg["max_items"]], states[cfg["max_items"]:]

    need = [s["item"] for s in shown[: cfg["max_summarized"]] if not s["summary"]]
    summaries = summarize.summarize(need, ctx.cfg, ctx.cfg["llm"]["digest_model"])
    for s in shown:
        s["summary"] = s["summary"] or summaries.get(s["item"]["id"])

    title = f"Bản tin CVE {slot:%H:%M} ngày {slot:%d/%m/%Y}"
    base = f"reports/{slot:%Y/%m/%d}-{'AM' if slot.hour < 12 else 'PM'}"
    rel, n = f"{base}.md", 2
    while os.path.exists(os.path.join(ctx.root, rel)):
        rel, n = f"{base}-{n}.md", n + 1
    text = render.digest_markdown(shown, title, set(summaries))
    if overflow:
        text += f"\n_Còn {len(overflow)} CVE ưu tiên thấp hơn không hiển thị (giới hạn {cfg['max_items']}/bản tin)._\n"
    ctx.write(rel, text)
    missing = any(not s["summary"] for s in shown[: cfg["max_summarized"]])
    note = summarize.last_error if missing else None
    notify.telegram(render.telegram_digest(shown, title, ctx.github_url(rel), note=note), ctx.cfg, ctx.dry_run)
    for s in states:
        s["digested_at"] = ctx.now.isoformat()
        ctx.store.put(s)
    log.info("digest %s: %d items -> %s", slot, len(shown), rel)


def main():
    parser = argparse.ArgumentParser(prog="cvewatch")
    parser.add_argument("command", choices=["run", "digest", "backfill"])
    parser.add_argument("--root", default=".", help="repository root (config/, reports/, alerts/)")
    parser.add_argument("--data", default="data", help="state directory")
    parser.add_argument("--dry-run", action="store_true", help="print Telegram messages instead of sending")
    parser.add_argument("--no-digest", action="store_true", help="run: skip the digest even if a slot is due")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    ctx = Ctx(args)
    cursor = ctx.store.load_cursor()
    if args.command == "run":
        poll(ctx, cursor)
        followup(ctx)
        slot = current_slot(ctx)
        if not args.no_digest and cursor.get("last_digest_slot") != slot.isoformat():
            refresh_tracked(ctx)
            digest(ctx, slot)
            cursor["last_digest_slot"] = slot.isoformat()
    elif args.command == "digest":
        digest(ctx, ctx.local_now)
    else:
        backfill.run(ctx)
    removed = ctx.store.prune(ctx.cfg["retention"]["days"])
    if removed:
        log.info("pruned %d old CVE states", removed)
    ctx.store.save_cursor(cursor)
    if ctx.changed_main:
        render.update_readme(ctx.root)


if __name__ == "__main__":
    main()
