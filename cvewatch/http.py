import logging
import time

import requests

log = logging.getLogger(__name__)

_session = requests.Session()
_session.headers["User-Agent"] = "daily-news-cvewatch/1.0 (+https://github.com/trung2806/daily-news)"


def get(url, *, params=None, headers=None, timeout=60, retries=3):
    """GET with retry on network errors and 429/5xx. Raises on final failure."""
    last = None
    for attempt in range(retries):
        try:
            resp = _session.get(url, params=params, headers=headers, timeout=timeout)
            if resp.status_code == 429 or resp.status_code >= 500:
                last = requests.HTTPError(f"{resp.status_code} for {url}")
            else:
                resp.raise_for_status()
                return resp
        except (requests.ConnectionError, requests.Timeout) as exc:
            last = exc
        time.sleep(2 ** (attempt + 1))
    raise last


def get_json(url, **kwargs):
    return get(url, **kwargs).json()


def post_json(url, payload, timeout=30):
    resp = _session.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()
