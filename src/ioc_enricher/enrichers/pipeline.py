from __future__ import annotations

from .kev import enrich_records as enrich_kev_records
from .risk import enrich_records as enrich_risk_records
from .vt import enrich_records as enrich_vt_records
from ..utils.models import IOCRecord


def enrich_records(records: list[IOCRecord]) -> list[IOCRecord]:
    records = enrich_vt_records(records)
    records = enrich_kev_records(records)
    records = enrich_risk_records(records)
    return records
