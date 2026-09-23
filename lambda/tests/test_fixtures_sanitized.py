"""Fails if a real account ID or access key ID ever lands in a fixture."""

import re

from conftest import FIXTURES

ACCOUNT_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
KEY_ID_RE = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")


def test_fixtures_contain_only_placeholder_ids():
    for path in FIXTURES.glob("*.json"):
        text = path.read_text()
        accounts = set(ACCOUNT_RE.findall(text)) - {"123456789012"}
        assert not accounts, f"{path.name} has real account IDs, run scripts/sanitize_fixture.py"
        assert not KEY_ID_RE.search(text), f"{path.name} has an access key ID, run scripts/sanitize_fixture.py"
