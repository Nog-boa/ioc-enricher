from __future__ import annotations

import base64
import os
import time
from dataclasses import replace

import requests
from dotenv import load_dotenv

from ..utils.models import IOCRecord

VT_API_BASE = "https://www.virustotal.com/api/v3"
MAX_RETRIES = 5
REQUEST_TIMEOUT_SECONDS = 15
BACKOFF_BASE_SECONDS = 1
SUPPORTED_VT_TYPES = {"ip", "domain", "url", "hash"}


def _build_path(record: IOCRecord) -> str | None:
    if record.ioc_type == "ip":
        return f"/ip_addresses/{record.ioc}"
    if record.ioc_type == "domain":
        return f"/domains/{record.ioc}"
    if record.ioc_type == "hash":
        return f"/files/{record.ioc}"
    if record.ioc_type == "url":
        url_id = base64.urlsafe_b64encode(record.ioc.encode("utf-8")).decode("ascii").rstrip("=")
        return f"/urls/{url_id}"
    return None


def _request_with_retry(session: requests.Session, url: str, headers: dict[str, str]) -> requests.Response:
    for attempt in range(MAX_RETRIES):
        try:
            response = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
        except requests.Timeout as exc:
            if attempt == MAX_RETRIES - 1:
                raise RuntimeError("timeout") from exc
            time.sleep(BACKOFF_BASE_SECONDS * (2**attempt))
            continue

        if response.status_code == 429:
            if attempt == MAX_RETRIES - 1:
                raise RuntimeError("rate_limited")
            time.sleep(BACKOFF_BASE_SECONDS * (2**attempt))
            continue

        return response

    raise RuntimeError("unexpected_retry_exhaustion")


def enrich_records(records: list[IOCRecord]) -> list[IOCRecord]:
    load_dotenv()
    api_key = os.getenv("VT_API_KEY", "").strip()

    enriched: list[IOCRecord] = []

    if not api_key:
        for record in records:
            if record.ioc_type not in SUPPORTED_VT_TYPES:
                enriched.append(
                    replace(
                        record,
                        vt_malicious="",
                        vt_suspicious="",
                        vt_harmless="",
                        vt_undetected="",
                        vt_error="",
                        vt_link="",
                    )
                )
                continue
            enriched.append(replace(record, vt_error="missing_vt_api_key"))
        return enriched

    headers = {"x-apikey": api_key}
    with requests.Session() as session:
        for record in records:
            if record.ioc_type not in SUPPORTED_VT_TYPES:
                enriched.append(
                    replace(
                        record,
                        vt_malicious="",
                        vt_suspicious="",
                        vt_harmless="",
                        vt_undetected="",
                        vt_error="",
                        vt_link="",
                    )
                )
                continue

            if record.error:
                enriched.append(replace(record, vt_error="skipped_due_to_parse_error"))
                continue

            path = _build_path(record)
            if not path:
                enriched.append(
                    replace(
                        record,
                        vt_malicious="",
                        vt_suspicious="",
                        vt_harmless="",
                        vt_undetected="",
                        vt_error="",
                        vt_link="",
                    )
                )
                continue

            url = f"{VT_API_BASE}{path}"
            try:
                response = _request_with_retry(session, url, headers)
            except RuntimeError as exc:
                enriched.append(replace(record, vt_error=str(exc)))
                continue
            except requests.RequestException as exc:
                enriched.append(replace(record, vt_error=f"request_error:{exc.__class__.__name__}"))
                continue

            if response.status_code >= 400:
                enriched.append(replace(record, vt_error=f"http_{response.status_code}", vt_link=url))
                continue

            try:
                payload = response.json()
            except ValueError:
                enriched.append(replace(record, vt_error="invalid_json", vt_link=url))
                continue

            stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            link = payload.get("data", {}).get("links", {}).get("self", url)

            enriched.append(
                replace(
                    record,
                    vt_malicious=int(stats.get("malicious", 0) or 0),
                    vt_suspicious=int(stats.get("suspicious", 0) or 0),
                    vt_harmless=int(stats.get("harmless", 0) or 0),
                    vt_undetected=int(stats.get("undetected", 0) or 0),
                    vt_error="",
                    vt_link=link,
                )
            )

    return enriched
