from __future__ import annotations

from dataclasses import replace

from ..utils.models import IOCRecord


def _to_int(value: object) -> int:
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _is_kev_true(value: str) -> bool:
    return str(value).strip().lower() == "true"


def enrich_records(records: list[IOCRecord]) -> list[IOCRecord]:
    enriched: list[IOCRecord] = []
    for record in records:
        vt_malicious = _to_int(record.vt_malicious)
        kev_exploited = _is_kev_true(record.kev_exploited)

        if kev_exploited and vt_malicious >= 3:
            risk_priority = "CRITICAL"
        elif vt_malicious >= 5:
            risk_priority = "HIGH"
        elif kev_exploited:
            risk_priority = "HIGH"
        elif vt_malicious in {1, 2, 3, 4}:
            risk_priority = "MEDIUM"
        else:
            risk_priority = "LOW"

        enriched.append(replace(record, risk_priority=risk_priority))
    return enriched
