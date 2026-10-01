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

"""The tenant-state gate on the MCP door (§3.4c).

This is the THIRD implementation of the rule — the two C++ doors share a header
verbatim, and that header does not reach Python. §3.4c names that exact risk:
"adding a check to N doors is N chances to add it subtly differently, and one
chance to forget a door entirely."

So `test_the_state_names_match_the_cpp_doors` PARSES the C++ header and compares.
If a state is added or renamed there and not here, this fails rather than this
door quietly admitting something the other two refuse.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from share_service import tenant_state as ts
from share_service.tenant_state import TenantStateGate

CPP_POLICY = (pathlib.Path(__file__).resolve().parents[3]
              / "http_bridge" / "include" / "tenant_state_policy.h")


class _Source:
    def __init__(self, state="live", found=True, raises=None):
        self.state, self.found, self.raises = state, found, raises
        self.calls = 0

    def tenant_state(self, tenant):
        self.calls += 1
        if self.raises:
            raise self.raises
        return {"found": self.found, "state": self.state, "admits": self.state == "live"}


# ── only live admits ───────────────────────────────────────────────────────


def test_only_live_admits():
    assert ts.admits(ts.LIVE)
    for s in (ts.REQUESTED, ts.AWAITING_DNS, ts.PROVISIONING, ts.SUSPENDED,
              ts.DECOMMISSIONING, ts.DECOMMISSIONED):
        assert not ts.admits(s), f"{s} must not admit"


def test_a_suspended_tenant_is_refused():
    ok, reason = TenantStateGate(_Source("suspended")).admits("acme")
    assert not ok and reason == "this tenant is suspended"


def test_a_half_built_tenant_is_not_reachable():
    ok, reason = TenantStateGate(_Source("provisioning")).admits("acme")
    assert not ok and "provisioned" in reason


def test_a_decommissioned_tenant_is_not_a_way_back_in():
    assert not TenantStateGate(_Source("decommissioned")).admits("acme")[0]


def test_live_admits():
    ok, reason = TenantStateGate(_Source("live")).admits("acme")
    assert ok and reason == ""


# ── fail closed ────────────────────────────────────────────────────────────


def test_an_unreachable_core_refuses():
    # §3.4c property 1: "allow on error" is how a suspended tenant gets admitted.
    ok, reason = TenantStateGate(_Source(raises=RuntimeError("core down"))).admits("acme")
    assert not ok
    assert "could not be determined" in reason
    assert "suspended" not in reason, "a failed lookup must not claim a suspension"


def test_a_tenant_with_no_registry_row_refuses():
    ok, _ = TenantStateGate(_Source(found=False)).admits("nosuch")
    assert not ok


def test_an_unknown_state_refuses():
    # The allowlist-of-one makes this automatic: a state added to the registry
    # later is refused until this door learns about it.
    ok, reason = TenantStateGate(_Source("archived")).admits("acme")
    assert not ok and "not recognised" in reason


def test_an_empty_tenant_refuses():
    assert not TenantStateGate(_Source()).admits("")[0]


def test_no_source_configured_refuses_rather_than_allowing():
    # The check would otherwise be decorative on exactly the deployment that
    # forgot to wire it.
    ok, _ = TenantStateGate(None).admits("acme")
    assert not ok


# ── the cache, and its asymmetry ───────────────────────────────────────────


def test_an_admission_is_cached():
    src = _Source("live")
    clock = iter([0.0, 1.0, 2.0])
    g = TenantStateGate(src, clock=lambda: next(clock))
    assert g.admits("acme")[0]
    assert g.admits("acme")[0]
    assert src.calls == 1, "the second call should have come from the cache"


def test_a_refusal_expires_sooner_than_an_admission():
    # Restoring a tenant to service should not wait on a cache, while a
    # suspension already bit the moment it was read.
    assert ts.REFUSE_TTL_S < ts.ADMIT_TTL_S


def test_a_refusal_is_rechecked_after_its_shorter_ttl():
    src = _Source("suspended")
    t = [0.0]
    g = TenantStateGate(src, clock=lambda: t[0])
    assert not g.admits("acme")[0]
    t[0] = ts.REFUSE_TTL_S + 1
    src.state = "live"
    assert g.admits("acme")[0], "a restored tenant must be admitted after the refusal TTL"


def test_different_tenants_are_cached_apart():
    class PerTenant:
        def tenant_state(self, tenant):
            return {"found": True, "state": "live" if tenant == "ok" else "suspended"}

    g = TenantStateGate(PerTenant())
    assert g.admits("ok")[0]
    assert not g.admits("bad")[0]


# ── the cross-language pin ─────────────────────────────────────────────────


@pytest.mark.skipif(not CPP_POLICY.exists(),
                    reason="http_bridge not checked out beside this repo")
def test_the_state_names_match_the_cpp_doors():
    """Parse the C++ policy header and compare its state names with ours.

    This is what makes a third implementation safe. The two C++ doors share the
    header, so they cannot disagree with each other; only Python can drift, and
    the drift would be silent — this door admitting something the others refuse.
    """
    text = CPP_POLICY.read_text()
    cpp = set(re.findall(r'constexpr const char\* k\w+ = "([a-z_]+)";', text))
    assert cpp, "could not parse any state names from the C++ header"
    assert cpp == set(ts.KNOWN_STATES), (
        f"state names differ: C++ has {sorted(cpp - set(ts.KNOWN_STATES))} extra, "
        f"Python has {sorted(set(ts.KNOWN_STATES) - cpp)} extra")


@pytest.mark.skipif(not CPP_POLICY.exists(), reason="http_bridge not checked out")
def test_the_cpp_doors_also_admit_only_live():
    # The rule itself, not just the vocabulary. If the C++ side ever widened
    # `admits`, this door would be the strict one and the estate inconsistent.
    text = CPP_POLICY.read_text()
    body = text[text.index("inline bool admits("):]
    body = body[:body.index("}")]
    assert "state == kLive" in body
    assert "||" not in body, "the C++ side admits more than `live`; this door does not"
