from __future__ import annotations

from ioc_enricher.enrichers.risk import enrich_records
from ioc_enricher.utils.models import IOCRecord


def _score_record(*, kev_exploited: str, vt_malicious: int | str | None) -> str:
    record = IOCRecord(
        ioc="test-ioc",
        ioc_type="domain",
        timestamp="2026-01-01T00:00:00Z",
        error="",
        kev_exploited=kev_exploited,
        vt_malicious=vt_malicious,  # type: ignore[arg-type]
    )
    scored = enrich_records([record])[0]
    return scored.risk_priority


def test_risk_priority_critical_when_kev_true_and_vt_malicious_at_least_three() -> None:
    assert _score_record(kev_exploited="True", vt_malicious=3) == "CRITICAL"


def test_risk_priority_high_when_kev_false_and_vt_malicious_five_or_more() -> None:
    assert _score_record(kev_exploited="False", vt_malicious=6) == "HIGH"


def test_risk_priority_high_when_kev_true_and_vt_malicious_zero() -> None:
    assert _score_record(kev_exploited="True", vt_malicious=0) == "HIGH"


def test_risk_priority_medium_when_kev_false_and_vt_malicious_one_to_four() -> None:
    assert _score_record(kev_exploited="False", vt_malicious=1) == "MEDIUM"
    assert _score_record(kev_exploited="False", vt_malicious=2) == "MEDIUM"
    assert _score_record(kev_exploited="False", vt_malicious=3) == "MEDIUM"
    assert _score_record(kev_exploited="False", vt_malicious=4) == "MEDIUM"


def test_risk_priority_low_when_kev_false_and_vt_malicious_zero() -> None:
    assert _score_record(kev_exploited="False", vt_malicious=0) == "LOW"


def test_blank_or_invalid_vt_malicious_is_treated_as_zero() -> None:
    assert _score_record(kev_exploited="False", vt_malicious="") == "LOW"
    assert _score_record(kev_exploited="False", vt_malicious=None) == "LOW"
