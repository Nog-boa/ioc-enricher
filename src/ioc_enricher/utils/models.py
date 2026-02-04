from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IOCRecord:
    ioc: str
    ioc_type: str
    timestamp: str
    error: str
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_undetected: int = 0
    vt_error: str = ""
    vt_link: str = ""
    kev_exploited: str = ""
    kev_vendor: str = ""
    kev_product: str = ""
    kev_due_date: str = ""
    risk_priority: str = "LOW"
