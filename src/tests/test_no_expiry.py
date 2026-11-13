# Copyright (C) 2026 James Hickman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""`clamp_expiry(no_expiry=True)` — the "No expiry" choice on the Share tab.

A perpetual link is stored as a NULL expiry. The deployment can switch the
choice off (SHARE_ALLOW_NO_EXPIRY=0), and asking for it alongside an explicit
expiry is an error rather than a silent pick of one of the two.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from share_service import links
from share_service.config import Config


@pytest.fixture
def cfg(monkeypatch):
    monkeypatch.delenv("SHARE_ALLOW_NO_EXPIRY", raising=False)
    return Config()


def test_no_expiry_resolves_to_none(cfg):
    assert cfg.allow_no_expiry is True
    assert links.clamp_expiry(cfg, None, None, True) is None


def test_no_expiry_is_refused_when_the_deployment_disallows_it(monkeypatch):
    monkeypatch.setenv("SHARE_ALLOW_NO_EXPIRY", "0")
    with pytest.raises(ValueError, match="not allowed"):
        links.clamp_expiry(Config(), None, None, True)


def test_no_expiry_with_an_explicit_expiry_is_refused(cfg):
    with pytest.raises(ValueError, match="cannot be combined"):
        links.clamp_expiry(cfg, None, 7, True)
    with pytest.raises(ValueError, match="cannot be combined"):
        links.clamp_expiry(cfg, datetime.now(timezone.utc) + timedelta(days=1), None, True)


def test_without_no_expiry_the_cap_still_binds(cfg):
    got = links.clamp_expiry(cfg, None, cfg.max_ttl_days + 90)
    assert got <= datetime.now(timezone.utc) + timedelta(days=cfg.max_ttl_days, seconds=5)


def test_no_sql_reads_a_null_link_expiry_as_expired():
    """A bare `expires_at > now()` is NULL for a no-expiry link, i.e. false.
    One in the session open made every no-expiry link unredeemable while every
    other path reported it active. Session/audience tables keep a NOT NULL
    expiry, so the check is confined to statements that touch share_links."""
    src = Path(links.__file__).parent
    bare = re.compile(r"(?<![\w.])(?:l\.)?expires_at\s*>\s*now\(\)")
    guarded = re.compile(r"expires_at IS NULL OR (?:l\.)?expires_at\s*>\s*now\(\)")
    offenders = []
    for f in sorted(src.glob("*.py")):
        text = f.read_text()
        for stmt in re.findall(r'"""(.*?)"""', text, re.S):
            if "share_links" not in stmt:
                continue
            if len(bare.findall(stmt)) > len(guarded.findall(stmt)):
                offenders.append(f"{f.name}: {' '.join(stmt.split())[:120]}")
    assert offenders == []
