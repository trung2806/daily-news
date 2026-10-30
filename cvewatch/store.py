"""State on disk: data/cursor.json plus one small file per tracked CVE (git-friendly diffs)."""
import json
import os
from datetime import datetime, timedelta, timezone


class Store:
    def __init__(self, root):
        self.root = root
        self.cve_dir = os.path.join(root, "cves")
        os.makedirs(self.cve_dir, exist_ok=True)

    def _path(self, cve_id):
        return os.path.join(self.cve_dir, f"{cve_id}.json")

    @staticmethod
    def _read(path, default):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return default

    @staticmethod
    def _write(path, data):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)

    def load_cursor(self):
        return self._read(os.path.join(self.root, "cursor.json"), {})

    def save_cursor(self, cursor):
        self._write(os.path.join(self.root, "cursor.json"), cursor)

    def tracked_ids(self):
        return {name[:-5] for name in os.listdir(self.cve_dir) if name.endswith(".json")}

    def get(self, cve_id):
        return self._read(self._path(cve_id), None)

    def put(self, state):
        self._write(self._path(state["item"]["id"]), state)

    def all(self):
        return [s for s in (self.get(i) for i in sorted(self.tracked_ids())) if s]

    def prune(self, days):
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        removed = 0
        for state in self.all():
            if datetime.fromisoformat(state["first_seen"]) < cutoff:
                os.remove(self._path(state["item"]["id"]))
                removed += 1
        return removed
