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

"""Which origin a minted link points at (spec §8.3).

The bug these cover: a link minted while working in tenant `acme` came out on
whatever origin the SPA happened to be loaded from — the default tenant's, in
practice, because the SPA switches tenant with an `X-Tenant` header and does not
navigate. The link still redeemed (the public route resolves the tenant from the
cross-tenant directory), so nothing failed loudly; it simply sent the recipient
to the wrong tenant's front door.

Pure unit tests: the origin is a function of config + request headers, so none
of this needs the live stack.
"""
from __future__ import annotations

from types import SimpleNamespace

from share_service.urls import tenant_origin


class _Cfg:
    def __init__(self, public_base_url="", tenant_base_domain=""):
        self.public_base_url = public_base_url
        self.tenant_base_domain = tenant_base_domain


def _req(host="default.example.com", proto="https", scheme="http"):
    """A request as it reaches this service: nginx forwards over plain http and
    states the real scheme in X-Forwarded-Proto."""
    headers = {"host": host}
    if proto:
        headers["x-forwarded-proto"] = proto
    return SimpleNamespace(headers=headers,
                           url=SimpleNamespace(netloc=host, scheme=scheme))


# --- the reported bug ------------------------------------------------------

def test_the_link_names_the_active_tenant_not_the_browsers_origin():
    """The whole bug in one line: creating in `acme` from a browser still on
    the default tenant's subdomain must not mint an `acme` link on it."""
    cfg = _Cfg(tenant_base_domain="example.com")
    assert tenant_origin(cfg, _req(host="default.example.com"), "acme") \
        == "https://acme.example.com"


def test_a_placeholder_in_the_configured_base_is_substituted():
    cfg = _Cfg(public_base_url="https://{tenant}.example.com")
    assert tenant_origin(cfg, _req(), "acme") == "https://acme.example.com"


def test_the_placeholder_works_for_a_separate_download_host():
    """§8.3's `dl.<base>` split, per tenant rather than shared."""
    cfg = _Cfg(public_base_url="https://dl.{tenant}.example.com/")
    assert tenant_origin(cfg, _req(), "acme") == "https://dl.acme.example.com"


def test_the_default_tenant_is_not_a_special_case():
    cfg = _Cfg(tenant_base_domain="example.com")
    assert tenant_origin(cfg, _req(host="acme.example.com"), "default") \
        == "https://default.example.com"


# --- what must NOT change --------------------------------------------------

def test_a_fixed_configured_base_still_wins_for_every_tenant():
    """No placeholder means the deployment asked for one origin. §8.3 depends
    on that staying true — links already in the wild point at it."""
    cfg = _Cfg(public_base_url="https://dl.example.com", tenant_base_domain="example.com")
    assert tenant_origin(cfg, _req(), "acme") == "https://dl.example.com"


def test_with_nothing_configured_it_is_the_request_origin_as_before():
    assert tenant_origin(_Cfg(), _req(host="acme.example.com"), "acme") \
        == "https://acme.example.com"


# --- the scheme, which the proxy is the only witness to --------------------

def test_the_forwarded_scheme_is_honoured():
    """uvicorn trusts X-Forwarded-Proto only from forwarded_allow_ips
    (127.0.0.1), which nginx on a container network is not — so without this
    an https deployment mints http:// links."""
    assert tenant_origin(_Cfg(), _req(host="acme.example.com",
                                      proto="https", scheme="http"), "acme") \
        == "https://acme.example.com"


def test_without_a_forwarded_scheme_the_requests_own_is_used():
    assert tenant_origin(_Cfg(), _req(host="acme.example.com",
                                      proto=None, scheme="http"), "acme") \
        == "http://acme.example.com"


def test_a_port_on_the_request_survives_composition():
    """Dev runs the stack on a port; a composed origin that drops it is
    unreachable."""
    cfg = _Cfg(tenant_base_domain="localtest.me")
    assert tenant_origin(cfg, _req(host="default.localtest.me:8443"), "acme") \
        == "https://acme.localtest.me:8443"


# --- a tenant name is not automatically a hostname -------------------------

def test_a_tenant_that_is_not_a_label_is_never_spliced_into_a_host():
    """X-Tenant is taken as given (`auth.get_caller`), so the name reaching
    here is only as well-formed as the caller chose to make it."""
    cfg = _Cfg(tenant_base_domain="example.com")
    for hostile in ("evil.com", "a/b", "acme..", "", "acme_1", "-acme"):
        assert tenant_origin(cfg, _req(host="default.example.com"), hostile) \
            == "https://default.example.com"


def test_a_hostile_tenant_does_not_corrupt_a_placeholder_base_either():
    cfg = _Cfg(public_base_url="https://{tenant}.example.com")
    assert tenant_origin(cfg, _req(host="default.example.com"), "evil.com/x") \
        == "https://default.example.com"
