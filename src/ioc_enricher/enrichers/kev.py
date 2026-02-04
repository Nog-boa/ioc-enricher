from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path

import requests

from ..utils.models import IOCRecord

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT_SECONDS = 20
CACHE_MAX_AGE_SECONDS = 24 * 60 * 60
CACHE_PATH = Path(".cache") / "known_exploited_vulnerabilities.json"


def _build_kev_index(payload: dict) -> dict[str, dict]:
    vulnerabilities = payload.get("vulnerabilities", [])
    index: dict[str, dict] = {}
    for item in vulnerabilities:
        cve_id = str(item.get("cveID", "")).strip().upper()
        if cve_id:
            index[cve_id] = item
    return index


def _load_kev_payload() -> tuple[dict | None, str]:
    now = time.time()
    if CACHE_PATH.exists():
        try:
            age_seconds = now - CACHE_PATH.stat().st_mtime
            if age_seconds <= CACHE_MAX_AGE_SECONDS:
                return json.loads(CACHE_PATH.read_text(encoding="utf-8")), ""
        except (OSError, json.JSONDecodeError):
            pass

    try:
        response = requests.get(KEV_FEED_URL, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        payload = response.json()
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(json.dumps(payload), encoding="utf-8")
        return payload, ""
    except (requests.RequestException, ValueError, OSError):
        # Fall back to any existing cache, even if stale.
        if CACHE_PATH.exists():
            try:
                return json.loads(CACHE_PATH.read_text(encoding="utf-8")), ""
            except (OSError, json.JSONDecodeError):
                pass
        return None, "kev_unavailable"


def enrich_records(records: list[IOCRecord]) -> list[IOCRecord]:
    payload, load_error = _load_kev_payload()
    kev_index = _build_kev_index(payload) if payload else {}
    enriched: list[IOCRecord] = []

    for record in records:
        if record.ioc_type != "cve":
            enriched.append(record)
            continue

        if load_error:
            enriched.append(replace(record, kev_exploited="error", kev_vendor=load_error))
            continue

        kev_entry = kev_index.get(record.ioc.upper())
        if not kev_entry:
            enriched.append(replace(record, kev_exploited="False"))
            continue

        enriched.append(
            replace(
                record,
                kev_exploited="True",
                kev_vendor=str(kev_entry.get("vendorProject", "")),
                kev_product=str(kev_entry.get("product", "")),
                kev_due_date=str(kev_entry.get("dueDate", "")),
            )
        )

    return enriched
