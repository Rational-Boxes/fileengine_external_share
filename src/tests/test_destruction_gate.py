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

"""Every data-destruction operation is gated to erasure_admins.

Erasing an address from the audience rosters destroys rows, so being a tenant
administrator is not enough — the same rule the core applies to ERASE and
CULL_VERSIONS. The refusal happens before any database or audit work, so these
run without a dev stack.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from share_service import api
from share_service.auth import Caller, get_caller
from share_service.config import Config


def _client(roles):
    app = FastAPI()
    app.state.config = Config()
    app.include_router(api.router)
    app.dependency_overrides[get_caller] = lambda: Caller(user="u", tenant="acme", roles=roles)
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("roles", [
    ["users"],
    ["users", "administrators"],
    ["users", "administrators", "tenant_admin"],
])
def test_audience_erase_refused_without_erasure_admins(roles):
    r = _client(roles).post("/share/v1/admin/audience/erase", json={"email": "a@example.com"})
    assert r.status_code == 403
    assert "erasure_admins" in r.json()["detail"]


@pytest.mark.parametrize("roles", [
    ["users", "erasure_admins"],
    ["users", "Erasure_Admin"],   # the core role spelling, any case
    ["system_admin"],
])
def test_erasure_roles_are_recognised(roles):
    assert api.is_erasure_admin(Caller(user="u", tenant="acme", roles=roles))


def test_admin_role_config_cannot_widen_the_gate(monkeypatch):
    monkeypatch.setenv("SHARE_ADMIN_ROLES", "users")
    assert not api.is_erasure_admin(Caller(user="u", tenant="acme", roles=["users"]))
