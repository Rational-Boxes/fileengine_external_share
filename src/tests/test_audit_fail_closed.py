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

"""Audit is a hard dependency here (development plan §5.1, test 3).

The platform's usual emitter returns True when auditing is disabled so guarded
operations "never block". share_service must not inherit that: the core
attributes delegated activity to the creator, so this chain is the only record
that an access was external (spec §4.3). Auditing off and sharing on is not a
combination that may exist.
"""
from __future__ import annotations

import pytest

from share_service.audit import AuditEmitter, AuditUnavailable
from share_service.config import Config


class _Publisher:
    """Stands in for audit_service.publisher.AuditPublisher."""

    def __init__(self, accept: bool = True):
        self.accept = accept
        self.published: list[dict] = []

    def publish(self, **fields):
        self.published.append(fields)
        return self.accept


@pytest.fixture
def cfg() -> Config:
    return Config()


def test_disabled_auditing_means_unavailable_not_permissive(cfg, monkeypatch):
    """The deviation, stated as a test.

    ldap_manager's emitter would report success here so the guarded operation
    proceeds. For this service that would mean external downloads with no
    record anywhere that they were external.
    """
    monkeypatch.setenv("FILEENGINE_AUDIT_ENABLED", "false")
    emitter = AuditEmitter(Config())
    assert emitter.available is False
    assert emitter.emit(action="share_link_create", outcome="ok", actor="alice",
                        category="permission", tenant="default") is False


def test_emit_or_raise_blocks_when_the_stream_rejects(cfg):
    emitter = AuditEmitter(cfg, publisher=_Publisher(accept=False))
    with pytest.raises(AuditUnavailable):
        emitter.emit_or_raise(action="share_link_create", outcome="ok",
                              actor="alice", category="permission", tenant="default")


def test_emit_or_raise_blocks_when_there_is_no_publisher(cfg, monkeypatch):
    monkeypatch.setenv("FILEENGINE_AUDIT_ENABLED", "false")
    with pytest.raises(AuditUnavailable):
        AuditEmitter(Config()).emit_or_raise(
            action="share_link_redeem", outcome="ok", actor="share:x|bob@e.com",
            category="access", tenant="default")


def test_successful_emit_carries_the_service_iface(cfg):
    pub = _Publisher()
    emitter = AuditEmitter(cfg, publisher=pub)
    emitter.emit_or_raise(action="share_link_create", outcome="ok", actor="alice",
                          category="permission", tenant="default",
                          target_uid="uid-1", request_id="r-1")
    assert pub.published[0]["source_iface"] == "share"
    assert pub.published[0]["action"] == "share_link_create"
    # request_id is the join key to the core's own event for the same
    # operation, which will name the creator rather than the recipient.
    assert pub.published[0]["request_id"] == "r-1"


def test_emit_returns_false_rather_than_raising(cfg):
    """`emit` is the non-blocking form; callers guarding a fail-closed action
    use `emit_or_raise` so a forgotten check cannot let one through."""
    emitter = AuditEmitter(cfg, publisher=_Publisher(accept=False))
    assert emitter.emit(action="share_link_denied", outcome="denied",
                        actor="share:x", category="access", tenant="default") is False
