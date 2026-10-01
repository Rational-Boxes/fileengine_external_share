# Copyright (C) 2026 James Hickman <james@rationalboxes.com>
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
"""A suspended tenant's share links stop serving (§3.4c).

Found 2026-10-01: suspension reached every door that holds a user session, but a
public link is served by THIS service acting as the link's creator — no user
token anywhere — and nothing here asked the tenant's state. A suspended tenant's
links kept handing out its files to anyone holding one.

Every public route resolves its link through `_resolve`, so the check lives there,
AFTER the link is found: the tenant is the one whose schema actually held the
link, never the caller-supplied X-Tenant, which only ever narrows the lookup.
"""
from __future__ import annotations

import types

import pytest
from fastapi import HTTPException

from share_service import public
from share_service.tenant_state import TenantStateGate


class _Link:
    def status(self):
        return "active"


def _wire(monkeypatch, state, *, found=True):
    denied = []
    monkeypatch.setattr(public, "_cfg", lambda r: types.SimpleNamespace(
        enabled=True, default_tenant="default"))
    monkeypatch.setattr(public, "get_emitter", lambda c: types.SimpleNamespace(available=True))
    monkeypatch.setattr(public.db, "connect_for_tenant",
                        lambda c, t, provision=True: types.SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(public.links, "get", lambda conn, uid: _Link())
    monkeypatch.setattr(public.links, "secret_matches", lambda s, h: True)
    monkeypatch.setattr(public, "_secret_hash", lambda conn, uid: b"")
    monkeypatch.setattr(public, "_audit_denied",
                        lambda cfg, **kw: denied.append(kw["reason"]))
    gate = TenantStateGate(types.SimpleNamespace(
        tenant_state=lambda t: {"found": found, "state": state}))
    monkeypatch.setattr(public, "TENANT_GATE", gate)
    req = types.SimpleNamespace(headers={"x-tenant": "acme"},
                                client=types.SimpleNamespace(host="198.51.100.7"))
    return req, denied


def test_a_live_tenants_link_still_resolves(monkeypatch):
    req, denied = _wire(monkeypatch, "live")
    cfg, tenant, conn, link = public._resolve(req, "L1", "secret")
    assert tenant == "acme" and denied == []


def test_a_suspended_tenants_link_is_refused_with_the_uniform_404(monkeypatch):
    req, denied = _wire(monkeypatch, "suspended")
    with pytest.raises(HTTPException) as e:
        public._resolve(req, "L1", "secret")
    assert e.value.status_code == 404          # an outside caller learns nothing
    assert denied == ["tenant_not_live"]       # the audit record says why


def test_an_unknown_tenant_state_refuses(monkeypatch):
    req, denied = _wire(monkeypatch, "", found=False)
    with pytest.raises(HTTPException):
        public._resolve(req, "L1", "secret")
    assert denied == ["tenant_not_live"]
