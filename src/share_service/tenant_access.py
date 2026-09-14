"""The tenant-membership invariant, in one place.

Membership in a tenant **is** holding at least one LDAP group beneath that
tenant's ``ou``. There is no separate membership record to consult. Two rules
follow, and both halves matter:

  * **No groups in tenant T => no access to T**, whatever the credential type.
  * **Roles are the ``cn``s of the groups held IN T** — never a union across
    tenants.

Dropping the second rule is what made the first one meaningless. The role
search used to run against the whole tenant base and the caller then stamped
the requested tenant onto the result (``replace(identity, tenant=tenant)``), so
a member of tenant A's ``administrators`` group authenticated as an
administrator of tenant B simply by sending ``X-Tenant: B``. The equivalent on
the token path was resolving ``roles[tenant]`` to ``[]`` instead of refusing:
an authenticated caller in a tenant they do not belong to, which the core then
served under read-by-default.

The canonical implementation of this rule is the bridge's
``getRolesByTenant`` / ``tokenTenantMember`` pair (``http_bridge``); this module
is its Python counterpart, and is copied verbatim into each service that
accepts a credential.

**Service principals** are the one deliberate exception. They are
infrastructure identities (``FILEENGINE_SERVICE_PRINCIPALS``, defaulting to the
service's own configured agent), so the *admission* test cannot apply to them:
they may act in a tenant they hold no group in. It stops there. They still get
exactly the roles they hold IN that tenant — no more, and never a union across
tenants.

Blanking their roles instead was wrong, and broke production: the workers reach
the core as this principal, and the directory-wide search had been quietly
handing them ``system_admin``. Stripping every role turned that into
``PermissionDenied`` on operations they legitimately perform. The escalation to
remove was the CROSS-TENANT one; a service account that really is in a tenant's
group still holds it.
"""
from __future__ import annotations

import logging
from typing import Optional

try:                                    # ldap3 is absent in some unit-test envs
    from ldap3 import SUBTREE
    from ldap3.core.exceptions import LDAPException
except Exception:                       # pragma: no cover - exercised by import
    SUBTREE = "SUBTREE"

    class LDAPException(Exception):
        pass

log = logging.getLogger(__name__)


def tenant_role_base(cfg, tenant: str) -> str:
    """Where this tenant's groups live: ``ou=<tenant>,<tenant_base>``.

    Roles are per tenant and their CNs REPEAT across tenants — `administrators`,
    `engineering` and `accounting` all exist under more than one `ou=` on the
    deployment. Searching the whole tenant base therefore returns a union: a
    user who is `administrators` in one tenant looked like an administrator in
    every tenant. Scoping the base is what makes the answer mean "in THIS
    tenant".
    """
    return f"ou={tenant},{cfg.ldap_tenant_base}"


def roles_in_tenant(svc, cfg, user_dn: str, tenant: str) -> list[str]:
    """The user's group ``cn``s within ``tenant``. **Empty means NOT A MEMBER.**

    That emptiness is the membership test — there is no separate record. Fails
    closed: a search error yields no roles, i.e. no access.
    """
    if not tenant:
        return []
    roles: list[str] = []
    try:
        svc.search(tenant_role_base(cfg, tenant),
                   f"(&(objectClass=groupOfNames)(member={user_dn}))",
                   search_scope=SUBTREE, attributes=["cn"])
    except LDAPException:
        log.warning("tenant_access: role lookup failed for %s in %s",
                    user_dn, tenant, exc_info=True)
        return []
    for entry in svc.entries:
        cn = str(entry.cn)
        if cn and cn not in roles:
            roles.append(cn)
    if "administrators" in roles and "system_admin" not in roles:
        roles.append("system_admin")
    return roles


def service_principals(cfg) -> set[str]:
    """Identities exempt from the membership rule, lowercased.

    Configured explicitly so the exemption is auditable. Defaults to the
    service's own agent account, which is how it reaches its peers.
    """
    raw = getattr(cfg, "service_principals", "") or ""
    names = {p.strip().lower() for p in raw.split(",") if p.strip()}
    agent = (getattr(cfg, "agent_user", "") or "").strip().lower()
    if agent:
        names.add(agent)
    return names


def is_service_principal(cfg, username: str) -> bool:
    """Whether ``username`` is an infrastructure identity rather than a member.

    Matched case-insensitively against uid *and* mail spellings: the platform
    hands services an email as their identity, but a bind may name either.
    """
    name = (username or "").strip().lower()
    return bool(name) and name in service_principals(cfg)


def scope_claims_to_tenant(claims: dict, tenant: str) -> Optional[tuple[str, list[str]]]:
    """``(user, roles-in-tenant)`` from verified bridge claims, or ``None`` if
    the token does not attest membership of ``tenant``.

    The bridge mints ``roles`` as a ``{tenant: [roles]}`` map covering every
    tenant the user belongs to, and refuses to issue a token at all to a user
    with no groups anywhere. So a tenant absent from that map is one the caller
    is not a member of, and the answer is refusal — not an empty role list.
    Mirrors ``tokenTenantMember`` in the bridge.

    Tokens carrying no ``roles`` map are not bridge sessions (service tokens,
    download tickets); membership is not asserted for them here and the caller
    remains responsible for whatever narrower authority they carry.
    """
    user = claims.get("sub")
    if not user:
        return None
    active = tenant or claims.get("tenant") or "default"
    roles_map = claims.get("roles")
    if isinstance(roles_map, dict):
        if active not in roles_map:
            return None
        return user, list(roles_map.get(active) or [])
    return user, []
