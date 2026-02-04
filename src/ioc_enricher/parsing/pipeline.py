from __future__ import annotations

from pathlib import Path

from ..utils.ioc import detect_ioc, utc_timestamp
from ..utils.models import IOCRecord
from .reader import iter_ioc_strings


def parse_input(path: Path) -> list[IOCRecord]:
    timestamp = utc_timestamp()
    records: list[IOCRecord] = []
    for raw in iter_ioc_strings(path):
        normalized, ioc_type, error = detect_ioc(raw)
        record = IOCRecord(
            ioc=normalized if normalized else raw.strip(),
            ioc_type=ioc_type,
            timestamp=timestamp,
            error=error,
        )
        records.append(record)
    return records
