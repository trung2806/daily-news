import re

import yaml

_FIELDS = ("vendor", "product", "text")


class Watchlist:
    def __init__(self, groups):
        # groups: {key: {"label": str, "entries": [{field: compiled regex}]}}
        self.groups = groups

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        groups = {}
        for key, group in (raw.get("groups") or {}).items():
            entries = []
            for entry in group.get("entries") or []:
                unknown = set(entry) - set(_FIELDS)
                if unknown or not entry:
                    raise ValueError(f"watchlist {key}: invalid entry {entry}")
                entries.append({f: re.compile(str(entry[f]), re.I) for f in _FIELDS if f in entry})
            groups[key] = {"label": group.get("label", key), "entries": entries}
        return cls(groups)

    @staticmethod
    def _entry_matches(entry, pairs, text):
        if "text" in entry and not entry["text"].search(text):
            return False
        if "vendor" not in entry and "product" not in entry:
            return True
        for vendor, product in pairs:
            if "vendor" in entry and not entry["vendor"].search(vendor):
                continue
            if "product" in entry and not entry["product"].search(product):
                continue
            return True
        return False

    def match(self, item):
        """Return the labels of all groups the item belongs to."""
        pairs = [(a["vendor"], a["product"]) for a in item["affected"]]
        if item.get("kev"):
            pairs.append((item["kev"].get("vendor") or "", item["kev"].get("product") or ""))
        text = f"{item['title']}\n{item['description']}"
        return [
            g["label"]
            for g in self.groups.values()
            if any(self._entry_matches(e, pairs, text) for e in g["entries"])
        ]
