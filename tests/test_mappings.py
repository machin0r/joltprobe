from __future__ import annotations

from joltprobe.checks import ALL_CHECKS, CHECK_BY_ID
from joltprobe.checks.mappings import CWE_MAP


def test_every_check_has_a_cwe():
    # Item 4: every registered check must map to at least one CWE so findings
    # carry an auditable classification.
    missing = [cls.id for cls in ALL_CHECKS if not cls.cwe]
    assert missing == [], f"checks missing a CWE classification: {missing}"


def test_cwe_values_are_wellformed():
    for cls in ALL_CHECKS:
        for cwe in cls.cwe:
            assert cwe.startswith("CWE-"), f"{cls.id}: {cwe!r} is not a CWE id"
            assert cwe.split("-", 1)[1].isdigit(), f"{cls.id}: {cwe!r} has no numeric id"


def test_cwe_map_has_no_orphan_entries():
    # A key in CWE_MAP that is not a real check id is a typo waiting to silently
    # drop a classification.
    orphans = [cid for cid in CWE_MAP if cid not in CHECK_BY_ID]
    assert orphans == [], f"CWE_MAP references unknown check ids: {orphans}"
