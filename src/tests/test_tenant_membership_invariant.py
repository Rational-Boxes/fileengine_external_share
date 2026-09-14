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

"""The tenant-membership invariant at this service's one door.

Membership in a tenant IS holding >=1 LDAP group beneath that tenant's ou, and
the bridge's token attests exactly that as a {tenant: [roles]} map. A tenant
absent from the map is one the caller does not belong to.

This service is bearer-only, so the map is the whole membership test. It used
to resolve a missing tenant to an empty role list, which authenticated the
caller into a tenant they had no groups in — and the core, being
read-by-default, then served it.
"""
from share_service import jwt_verify, tenant_access


def _claims(roles, sub="alice"):
    return {"sub": sub, "tenant": "alpha", "roles": roles}


def test_a_token_is_refused_for_a_tenant_it_does_not_attest():
    claims = _claims({"alpha": ["users"]})
    assert jwt_verify.identity_from_claims(claims, "alpha") == ("alice", ["users"])
    # Pre-fix: ("alice", []) — authenticated, in a tenant they do not belong to.
    assert jwt_verify.identity_from_claims(claims, "beta") is None


def test_roles_never_cross_tenants():
    claims = _claims({"alpha": ["administrators"], "beta": ["users"]})
    assert jwt_verify.identity_from_claims(claims, "beta") == ("alice", ["users"])
    assert jwt_verify.identity_from_claims(claims, "alpha") == ("alice", ["administrators"])


def test_membership_with_no_roles_is_still_membership():
    """The bridge mints a key only for a tenant the user belongs to."""
    assert jwt_verify.identity_from_claims(_claims({"alpha": []}), "alpha") == ("alice", [])


def test_no_subject_is_refused():
    assert jwt_verify.identity_from_claims({"roles": {"alpha": []}}, "alpha") is None


def test_an_empty_x_tenant_falls_back_to_the_tokens_own_tenant():
    claims = _claims({"alpha": ["users"]})
    assert jwt_verify.identity_from_claims(claims, "") == ("alice", ["users"])


def test_non_bridge_tokens_are_left_alone():
    """No roles map => not a bridge session; membership is not asserted here."""
    assert tenant_access.scope_claims_to_tenant({"sub": "svc"}, "alpha") == ("svc", [])


# --- the dependency the routes actually mount -------------------------------

def _fake_request(secret):
    """Enough of a Starlette Request for get_caller: config + client address."""
    cfg = type("C", (), {"jwt_secret": secret})()
    app = type("A", (), {"state": type("S", (), {"config": cfg})()})()
    return type("R", (), {"app": app, "headers": {}, "client": None})()


def _mint(secret, claims):
    import base64, hashlib, hmac, json

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b64(json.dumps(claims).encode())
    sig = b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def test_get_caller_forbids_a_tenant_the_token_does_not_attest(monkeypatch):
    import time

    from fastapi import HTTPException
    from share_service import auth, token_revocation

    secret = "s3cret"
    monkeypatch.setattr(token_revocation, "permits", lambda jti: True)
    monkeypatch.setattr(auth.token_revocation, "permits", lambda jti: True)

    tok = _mint(secret, {"sub": "alice", "tenant": "alpha", "jti": "j1",
                         "roles": {"alpha": ["users"]},
                         "exp": int(time.time()) + 600})
    req = _fake_request(secret)

    caller = auth.get_caller(req, f"Bearer {tok}", "alpha")
    assert caller.user == "alice" and caller.tenant == "alpha"

    try:
        auth.get_caller(req, f"Bearer {tok}", "beta")
    except HTTPException as e:
        # 403, as the bridge answers on the same condition — authenticated, but
        # not a member. Pre-fix this returned a Caller scoped to beta.
        assert e.status_code == 403
    else:
        raise AssertionError("a non-member was admitted to tenant beta")
