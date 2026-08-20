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

"""Retention sweep (spec §5.5).

Dead links are kept as audit evidence and purged after the window. The window
exists chiefly for the recipient addresses — people outside the organisation who
never asked to be in this database.
"""
from __future__ import annotations

import uuid

import pytest

from share_service import audit, db, links, retention
from share_service.config import Config

pytestmark = pytest.mark.live

USER = "testuser@rationalboxes.com"
TENANT = "default"


@pytest.fixture
def cfg() -> Config:
    c = Config()
    if not c.pg_host:
        pytest.skip("no Postgres configured")
    c.enabled = True
    return c


@pytest.fixture
def conn(cfg):
    c = db.connect_for_tenant(cfg, TENANT, provision=True)
    yield c
    c.close()


def _aged_link(cfg, conn, *, days_dead: int, revoked: bool = False,
               recipients=("outsider@example.com",)):
    """A link whose expiry is `days_dead` in the past."""
    made, _ = links.create(
        conn, kind=0, resource_uid=str(uuid.uuid4()), created_by=USER,
        expires_at=links.clamp_expiry(cfg, None, 1),
        recipients=list(recipients), max_uses=1)
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE share_links
                  SET expires_at = now() - make_interval(days => %s),
                      revoked_at = CASE WHEN %s THEN now() ELSE NULL END
                WHERE link_uid = %s""",
            (days_dead, revoked, made.link_uid))
    conn.commit()
    return made


def _exists(conn, link_uid) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM share_links WHERE link_uid = %s", (link_uid,))
        return cur.fetchone() is not None


def test_a_link_dead_longer_than_the_window_is_purged(cfg, conn):
    old = _aged_link(cfg, conn, days_dead=cfg.retention_days + 30)
    report = retention.sweep_tenant(cfg, TENANT)
    assert report["purged"] >= 1
    assert not _exists(conn, old.link_uid)


def test_a_recently_dead_link_is_kept_as_evidence(cfg, conn):
    """Expiry is not deletion. "Who did we ever share this with" is a question
    that arrives months later."""
    recent = _aged_link(cfg, conn, days_dead=1)
    retention.sweep_tenant(cfg, TENANT)
    assert _exists(conn, recent.link_uid)


def test_a_live_link_is_never_touched(cfg, conn):
    live, _ = links.create(
        conn, kind=0, resource_uid=str(uuid.uuid4()), created_by=USER,
        expires_at=links.clamp_expiry(cfg, None, 1),
        recipients=["still@example.com"], max_uses=1)
    retention.sweep_tenant(cfg, TENANT)
    assert _exists(conn, live.link_uid)


def test_a_revoked_link_ages_out_like_any_other(cfg, conn):
    revoked = _aged_link(cfg, conn, days_dead=cfg.retention_days + 5, revoked=True)
    retention.sweep_tenant(cfg, TENANT)
    assert not _exists(conn, revoked.link_uid)


def test_the_recipient_addresses_go_with_it(cfg, conn):
    """The actual point of the window. Everything else here is disk."""
    old = _aged_link(cfg, conn, days_dead=cfg.retention_days + 5,
                     recipients=["someone-outside@contractor.example"])
    retention.sweep_tenant(cfg, TENANT)
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM share_link_recipients WHERE link_uid = %s",
                    (old.link_uid,))
        assert cur.fetchone()[0] == 0


def test_the_purge_is_fail_closed_on_audit(cfg, conn, monkeypatch):
    """A row whose deletion cannot be RECORDED is not deleted.

    Deleting the only record that a link existed, without recording that it
    existed, is precisely the failure this service is built to prevent — so the
    row stays and the next pass retries it.
    """
    old = _aged_link(cfg, conn, days_dead=cfg.retention_days + 10)

    class Refusing:
        available = True

        def emit_or_raise(self, **kw):
            raise audit.AuditUnavailable("stream down")

    monkeypatch.setattr(retention, "get_emitter", lambda _c: Refusing())
    report = retention.sweep_tenant(cfg, TENANT)
    assert report["purged"] == 0
    assert report["skipped"] >= 1
    assert _exists(conn, old.link_uid), "an unauditable purge must not happen"


def test_a_bounded_pass_reports_that_more_remain(cfg, conn):
    """Bounded per call: the first sweep after this ships could face a year of
    rows, and one unbounded DELETE holding locks across the table is how a
    background tidy-up becomes an outage."""
    for _ in range(3):
        _aged_link(cfg, conn, days_dead=cfg.retention_days + 40)
    report = retention.sweep_tenant(cfg, TENANT, limit=2)
    assert report["purged"] == 2
    assert report["remaining"] is True


def test_retention_can_be_switched_off(cfg, conn):
    old = _aged_link(cfg, conn, days_dead=cfg.retention_days + 60)
    cfg.retention_days = 0
    report = retention.sweep_tenant(cfg, TENANT)
    assert report.get("disabled") is True
    assert _exists(conn, old.link_uid)


def test_one_bad_tenant_does_not_stop_the_others(cfg):
    """A sweep is a background tidy-up; a schema that will not open must not
    take the rest of the deployment's cleanup with it."""
    out = retention.sweep(cfg, ["definitely-not-a-tenant\x00bad", TENANT])
    assert len(out) == 2
    assert any("error" in r or r.get("tenant") == TENANT for r in out)
