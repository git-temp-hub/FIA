"""
Exact-match IOC correlation tests.

Address membership is an exact predicate. An embedding of "109.21.12.0/24" is
no closer to 109.21.12.44 than to any other network row, so similarity cannot
answer Q7 and a near-miss must never read as a hit.
"""

from __future__ import annotations

import json

import pytest

from app.services.ioc_matching import (
    AddressMatch,
    NetworkScan,
    format_missing_indicator_set,
    format_network_scan,
    load_indicator_sets,
    networks_in_question,
    parse_networks,
)


# ------------------------------------------------------------------
# Indicators from the question
# ------------------------------------------------------------------

def test_cidr_in_question_is_extracted():
    networks = networks_in_question(
        "Any connections to the malicious range 109.21.12.0/24?"
    )
    assert [str(network) for network in networks] == ["109.21.12.0/24"]


def test_bare_address_becomes_a_single_host_network():
    networks = networks_in_question("Did the host contact 203.0.113.9?")
    assert [str(network) for network in networks] == ["203.0.113.9/32"]


def test_cidr_is_not_truncated_to_its_base_address():
    """
    Matching the bare-address pattern first would reduce "10.1.2.0/24" to
    "10.1.2.0", silently narrowing a whole range to one host.
    """
    networks = networks_in_question("traffic to 10.1.2.0/24 please")
    assert [str(network) for network in networks] == ["10.1.2.0/24"]


def test_question_without_an_address_yields_nothing():
    assert networks_in_question("What processes were running?") == ()
    assert networks_in_question("") == ()


def test_unparseable_values_are_skipped_not_fatal():
    networks = parse_networks(["10.0.0.0/8", "not-an-ip", "", "999.1.1.1"])
    assert [str(network) for network in networks] == ["10.0.0.0/8"]


# ------------------------------------------------------------------
# Containment
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "address,inside",
    [
        ("109.21.12.44", True),
        ("109.21.12.0", True),
        ("109.21.12.255", True),
        # The near-miss that a similarity search would happily return.
        ("109.21.120.44", False),
        ("109.21.13.44", False),
        ("109.2.12.44", False),
    ],
)
def test_membership_is_numeric_not_textual(address, inside):
    import ipaddress

    network = ipaddress.ip_network("109.21.12.0/24")
    assert (ipaddress.ip_address(address) in network) is inside


# ------------------------------------------------------------------
# Indicator sets on disk
# ------------------------------------------------------------------

def test_indicator_directory_ships_no_indicators():
    """
    The platform must not bundle threat-actor indicators. A fabricated
    indicator produces a confident answer about infrastructure that does not
    exist.
    """
    assert load_indicator_sets() == []


def test_supplied_set_is_loaded(tmp_path):
    (tmp_path / "dept.json").write_text(
        json.dumps(
            {
                "name": "Dept advisory",
                "source": "CERT advisory 2026-041",
                "networks": ["203.0.113.0/24", "198.51.100.17"],
            }
        ),
        encoding="utf-8",
    )
    sets = load_indicator_sets(tmp_path)
    assert len(sets) == 1
    assert sets[0].name == "Dept advisory"
    assert len(sets[0]) == 2


def test_malformed_set_is_skipped(tmp_path):
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "good.json").write_text(
        json.dumps({"name": "ok", "networks": ["10.0.0.0/8"]}), encoding="utf-8"
    )
    sets = load_indicator_sets(tmp_path)
    assert [entry.name for entry in sets] == ["ok"]


def test_set_without_usable_networks_is_ignored(tmp_path):
    (tmp_path / "empty.json").write_text(
        json.dumps({"name": "empty", "networks": []}), encoding="utf-8"
    )
    assert load_indicator_sets(tmp_path) == []


# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------

def _scan(**kwargs) -> NetworkScan:
    defaults = {
        "rows_examined": 431,
        "distinct_addresses": 68,
        "networks_tested": parse_networks(["109.21.12.0/24"]),
        "plugins_available": ("windows.netscan",),
    }
    defaults.update(kwargs)
    return NetworkScan(**defaults)


def test_searched_range_with_no_hit_is_a_meaningful_negative():
    """The real D2F9 result: netscan ran, 68 addresses, none in range."""
    block = format_network_scan(_scan())
    assert "meaningful negative" in block
    assert "431" in block
    assert "not by text similarity" in block


def test_absent_network_evidence_is_not_a_negative_finding():
    block = format_network_scan(
        _scan(rows_examined=0, distinct_addresses=0, plugins_available=())
    )
    assert "could NOT be evaluated" in block
    assert "not a negative finding" in block
    assert "meaningful negative" not in block


def test_hits_are_reported_with_their_range():
    block = format_network_scan(
        _scan(
            matches=[
                AddressMatch(
                    "109.21.12.44",
                    "109.21.12.0/24",
                    [7],
                    ["remote address 109.21.12.44 port 443 state ESTABLISHED"],
                )
            ]
        )
    )
    assert "109.21.12.44" in block
    assert "109.21.12.0/24" in block
    assert "exact matches, not similarities" in block


def test_no_indicator_supplied_blocks_any_claim():
    block = format_network_scan(_scan(networks_tested=()))
    assert "not evaluated" in block
    assert "Do not claim" in block


def test_missing_actor_set_refuses_attribution():
    block = format_missing_indicator_set("APT28")
    assert "APT28" in block
    assert "cannot be performed" in block
    assert "Do NOT attribute" in block
    # Generic findings must not be laundered into attribution.
    assert "injected memory" in block
