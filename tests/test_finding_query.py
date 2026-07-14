"""Tests for the findings-table read query (§8.2 backend)."""

from __future__ import annotations

from pathlib import Path

import pytest
from app.domain.enums import Severity
from app.services import create_account, run_scan
from app.services.finding_query import (
    FindingFilters,
    SortKey,
    parse_filters,
    parse_sort,
    query_findings,
    sort_to_query,
)

pytestmark = pytest.mark.integration

_SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _scanned_account(session) -> int:
    account = create_account(
        session,
        name="Acme Corp",
        source_type="file",
        source_config={
            "inventory_path": str(_SAMPLES / "users.csv"),
            "policies_path": str(_SAMPLES / "policies.json"),
            "logs_path": str(_SAMPLES / "auth.log"),
        },
    )
    run_scan(session, account.id)
    return account.id


# ---- pure parsing (no DB) ----

def test_parse_sort_default_when_empty() -> None:
    assert parse_sort(None) == [SortKey("risk", True), SortKey("severity", True)]
    assert parse_sort("") == [SortKey("risk", True), SortKey("severity", True)]


def test_parse_sort_signs_and_multicolumn() -> None:
    assert parse_sort("-risk,severity") == [SortKey("risk", True), SortKey("severity", False)]


def test_parse_sort_drops_unknown_columns() -> None:
    assert parse_sort("bogus") == [SortKey("risk", True), SortKey("severity", True)]
    assert parse_sort("bogus,title") == [SortKey("title", False)]


def test_sort_roundtrips() -> None:
    assert sort_to_query(parse_sort("-risk,title")) == "-risk,title"


def test_parse_filters_rejects_invalid_enum_values() -> None:
    f = parse_filters({"severity": ["CRITICAL", "NOPE"], "status": ["open"], "q": ["  hi "]})
    assert f.severity == ["CRITICAL"]
    assert f.status == ["open"]
    assert f.search == "hi"
    assert f.active


def test_empty_filters_not_active() -> None:
    assert not FindingFilters().active


# ---- against a real scan ----

def test_query_returns_latest_run_findings(db_session) -> None:
    account_id = _scanned_account(db_session)
    page = query_findings(db_session, account_id)
    assert page.run is not None
    assert page.total == len(page.rows) or page.total > page.page_size
    assert page.total > 10
    # facets cover the whole run, independent of the (empty) filter.
    assert sum(page.facets["severity"].values()) == page.total


def test_severity_filter_narrows(db_session) -> None:
    account_id = _scanned_account(db_session)
    full = query_findings(db_session, account_id)
    crit = query_findings(
        db_session, account_id, filters=FindingFilters(severity=[Severity.CRITICAL.value])
    )
    assert crit.total == full.facets["severity"].get("CRITICAL", 0)
    assert crit.total < full.total
    assert all(r.severity == "CRITICAL" for r in crit.rows)


def test_search_matches_principal(db_session) -> None:
    account_id = _scanned_account(db_session)
    page = query_findings(db_session, account_id, filters=FindingFilters(search="intern"))
    assert page.total >= 1
    # Search spans title OR principal, so every row matches on at least one.
    assert all(
        "intern" in (r.principal_uid or "").lower() or "intern" in r.title.lower()
        for r in page.rows
    )
    # At least one row matches specifically on the principal.
    assert any("intern" in (r.principal_uid or "").lower() for r in page.rows)


def test_search_no_match_yields_empty(db_session) -> None:
    account_id = _scanned_account(db_session)
    page = query_findings(db_session, account_id, filters=FindingFilters(search="zzz-no-match"))
    assert page.total == 0
    assert page.rows == []
    assert page.pages == 1


def test_sort_by_risk_desc_then_asc(db_session) -> None:
    account_id = _scanned_account(db_session)
    desc = query_findings(db_session, account_id, sort=[SortKey("risk", True)])
    asc = query_findings(db_session, account_id, sort=[SortKey("risk", False)])
    desc_scores = [r.risk_score for r in desc.rows]
    asc_scores = [r.risk_score for r in asc.rows]
    assert desc_scores == sorted(desc_scores, reverse=True)
    assert asc_scores == sorted(asc_scores)


def test_severity_sort_uses_rank_not_alphabetical(db_session) -> None:
    account_id = _scanned_account(db_session)
    page = query_findings(db_session, account_id, sort=[SortKey("severity", True)])
    ranks = [Severity(r.severity).rank for r in page.rows]
    assert ranks == sorted(ranks, reverse=True)  # CRITICAL first, not alphabetical


def test_pagination_windows(db_session) -> None:
    account_id = _scanned_account(db_session)
    p1 = query_findings(db_session, account_id, page=1, page_size=5)
    p2 = query_findings(db_session, account_id, page=2, page_size=5)
    assert len(p1.rows) == 5
    assert p1.start_index == 1 and p1.end_index == 5
    assert p2.start_index == 6
    assert {r.id for r in p1.rows}.isdisjoint({r.id for r in p2.rows})


def test_no_run_returns_empty_page(db_session) -> None:
    account = create_account(db_session, name="Empty", source_type="file", source_config={})
    page = query_findings(db_session, account.id)
    assert page.run is None
    assert page.total == 0
    assert page.rows == []
    assert page.facets == {}
