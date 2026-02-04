from __future__ import annotations

import csv
from pathlib import Path

from ..utils.models import IOCRecord

FIELDNAMES = [
    "ioc",
    "ioc_type",
    "timestamp",
    "error",
    "vt_malicious",
    "vt_suspicious",
    "vt_harmless",
    "vt_undetected",
    "vt_error",
    "vt_link",
    "kev_exploited",
    "kev_vendor",
    "kev_product",
    "kev_due_date",
    "risk_priority",
]


def write_records(path: Path, records: list[IOCRecord]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        for record in records:
            writer.writerow(
                {
                    "ioc": record.ioc,
                    "ioc_type": record.ioc_type,
                    "timestamp": record.timestamp,
                    "error": record.error,
                    "vt_malicious": record.vt_malicious,
                    "vt_suspicious": record.vt_suspicious,
                    "vt_harmless": record.vt_harmless,
                    "vt_undetected": record.vt_undetected,
                    "vt_error": record.vt_error,
                    "vt_link": record.vt_link,
                    "kev_exploited": record.kev_exploited,
                    "kev_vendor": record.kev_vendor,
                    "kev_product": record.kev_product,
                    "kev_due_date": record.kev_due_date,
                    "risk_priority": record.risk_priority,
                }
            )
