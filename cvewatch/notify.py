import logging
import os

from . import http

log = logging.getLogger(__name__)

TELEGRAM_LIMIT = 4000  # API max is 4096; keep headroom for entities


def _chunks(text):
    chunk = ""
    for line in text.split("\n"):
        if len(chunk) + len(line) + 1 > TELEGRAM_LIMIT and chunk:
            yield chunk
            chunk = ""
        chunk += line[:TELEGRAM_LIMIT] + "\n"
    if chunk.strip():
        yield chunk


def telegram(text, cfg, dry_run=False):
    """Send an HTML message. Returns True when delivered (or would be, in dry run)."""
    if dry_run:
        print("----- telegram (dry run) -----\n" + text + "\n------------------------------")
        return True
    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not cfg["telegram"].get("enabled", True) or not token or not chat:
        log.info("telegram disabled or not configured")
        return False
    ok = True
    for part in _chunks(text):
        try:
            http.post_json(f"https://api.telegram.org/bot{token}/sendMessage", {
                "chat_id": chat,
                "text": part,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            })
        except Exception as exc:
            # Do not log the URL: it contains the bot token.
            log.error("telegram send failed: %s", type(exc).__name__)
            ok = False
    return ok
