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

"""Environment loading + Config for share_service (spec §9).

Shared cross-service knobs keep the ``FILEENGINE_*`` prefix (gRPC, LDAP, Redis,
the audit stream, the JWT secret) so one login and one event bus span every
service. Service-private knobs use ``SHARE_*``.

**This service has no agent/service principal**, unlike folder_actions. Every
core call is delegated as the *link creator* (spec §4.1); an agent account would
be an identity outliving any particular creator's access, which is the
lingering-grant problem the authority re-check exists to prevent. The only LDAP
credentials here are the read-only service bind used to resolve an absent
creator's group memberships.
"""
from __future__ import annotations

import os


def load_dotenv(path: str = ".env") -> None:
    if not os.path.isfile(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), _strip_value(val))


def _strip_value(val: str) -> str:
    val = val.strip()
    if val[:1] in ("'", '"'):
        q = val[0]
        end = val.find(q, 1)
        return val[1:end] if end != -1 else val[1:]
    if val.startswith("#"):
        return ""
    hi = val.find(" #")
    if hi != -1:
        val = val[:hi]
    return val.strip()


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _first(*keys_and_default: str) -> str:
    *keys, default = keys_and_default
    for k in keys:
        v = os.environ.get(k)
        if v:
            return v
    return default


def _bool(key: str, default: bool = False) -> bool:
    v = os.environ.get(key)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


def _int(key: str, default: int) -> int:
    try:
        return int(_env(key, str(default)))
    except ValueError:
        return default


class Config:
    def __init__(self) -> None:
        # --- gRPC core (SHARED) -------------------------------------------
        # Delegated calls go here as the link creator. The core trusts its
        # caller (CLAUDE.md trust model), so this address must never leave the
        # internal network.
        self.grpc_host = _env("FILEENGINE_GRPC_HOST", "localhost")
        self.grpc_port = _env("FILEENGINE_GRPC_PORT", "50051")
        self.grpc_address = f"{self.grpc_host}:{self.grpc_port}"

        # --- LDAP (SHARED) ------------------------------------------------
        # Used read-only: resolve a creator's groups at creation and at
        # redemption (spec §6.3). No user credentials are ever held.
        self.ldap_uri = _env("FILEENGINE_LDAP_ENDPOINT", "ldap://localhost:1389")
        self.ldap_uri_replica = _env("FILEENGINE_LDAP_ENDPOINT_REPLICA", "")
        self.ldap_replica_enabled = bool(self.ldap_uri_replica)
        self.ldap_domain = _env("FILEENGINE_LDAP_DOMAIN", "dc=rationalboxes,dc=com")
        self.ldap_user_base = _env("FILEENGINE_LDAP_USER_BASE", "ou=users,dc=rationalboxes,dc=com")
        self.ldap_tenant_base = _env("FILEENGINE_LDAP_TENANT_BASE", "ou=tenants,dc=rationalboxes,dc=com")
        self.ldap_bind_dn = _env("FILEENGINE_LDAP_BIND_DN", "cn=admin,dc=rationalboxes,dc=com")
        self.ldap_bind_password = _env("FILEENGINE_LDAP_BIND_PASSWORD", "admin")

        # --- Bearer verification (SHARED) ---------------------------------
        # The same HS256 secret http_bridge signs its session tokens with.
        self.jwt_secret = _env("FILEENGINE_JWT_SECRET", "")
        self.jwt_issuer = _env("FILEENGINE_JWT_ISSUER", "fileengine-bridge")

        # --- Recipient OTP, via ldap_manager (SHARED seam) -----------------
        # That service owns the code and the recipient token; this one owns the
        # allowlist. Every call fails closed (spec §6.9).
        self.ldap_manager_url = _env("FILEENGINE_LDAP_MANAGER_URL",
                                     "http://localhost:8093")
        self.share_internal_secret = _first("SHARE_INTERNAL_SECRET",
                                            "MFA_INTERNAL_SECRET", "")
        self.otp_timeout_s = _int("SHARE_OTP_TIMEOUT_S", 5)
        # Tenant for a public request that carries no X-Tenant. In the stack
        # nginx sets it from the subdomain; this is the dev fallback.
        self.default_tenant = _env("SHARE_DEFAULT_TENANT", "default")
        self.otp_ttl_seconds = _int("SHARE_OTP_TTL_SECONDS", 600)

        # --- Audit (SHARED) -----------------------------------------------
        # NOT optional here: the audit chain is the only record that an access
        # was external (spec §4.3), so auditing off == sharing off (§5.1 of the
        # development plan). `audit_enabled = False` disables the FEATURE, it
        # does not quietly disable the recording.
        self.audit_enabled = _bool("FILEENGINE_AUDIT_ENABLED", True)

        # --- Creator notifications (SHARED stream, PRIVATE selection) ------
        # Share events are published onto the same stream the core uses, where
        # discussion's consumer already listens (spec §10.6). No new transport.
        #
        # WHICH events raise an attention item is decided HERE and nowhere else:
        # the consumer raises whatever arrives, so an operator turning one on
        # sees it take effect rather than hitting a second gate downstream.
        self.redis_host = _env("FILEENGINE_REDIS_HOST", "localhost")
        self.redis_port = _int("FILEENGINE_REDIS_PORT", 6379)
        self.redis_password = _env("FILEENGINE_REDIS_PASSWORD", "")
        self.redis_db = _int("FILEENGINE_REDIS_DB", 0)
        self.events_stream = _env("FILEENGINE_EVENTS_STREAM", "fileengine:events")
        # budget_exhausted / expiry_soon are available and OFF by default —
        # they are the two most likely to become noise (spec §9).
        self.attention_events = tuple(
            e.strip() for e in
            _env("SHARE_ATTENTION_EVENTS",
                 "drop_received,otp_send_failed,link_dead,first_redemption").split(",")
            if e.strip())

        # --- This service's own Postgres (PRIVATE SHARE_*) -----------------
        self.pg_host = _env("SHARE_PG_HOST", "localhost")
        self.pg_port = _int("SHARE_PG_PORT", 5434)
        self.pg_database = _env("SHARE_PG_DATABASE", "share_service")
        self.pg_user = _env("SHARE_PG_USER", "fileengine_user")
        self.pg_password = _env("SHARE_PG_PASSWORD", "fileengine_password")
        self.pg_replica_host = _env("SHARE_PG_REPLICA_HOST", "")
        self.pg_replica_port = _int("SHARE_PG_REPLICA_PORT", self.pg_port)

        # --- Service surface ----------------------------------------------
        self.api_host = _env("SHARE_API_HOST", "0.0.0.0")
        self.api_port = _int("SHARE_API_PORT", 8101)
        # Monitoring is unauthenticated (a scraper cannot present a token), so
        # it binds loopback-only by platform convention. Do not widen this.
        self.monitoring_host = _env("SHARE_MONITORING_HOST", "127.0.0.1")
        self.monitoring_port = _int("SHARE_MONITORING_PORT", 8102)

        # --- Feature switches + policy (spec §9) --------------------------
        # Off by default: an unauthenticated door is opt-in.
        self.enabled = _bool("SHARE_ENABLED", False)
        # The LDAP group whose members may mint links (spec §8.1). Per-user
        # gate; the per-resource gate is a CheckPermission on the target.
        self.ldap_group = _env("SHARE_LDAP_GROUP", "share_external")
        # Roles that must never reach a delegated call (spec §6.3). The core
        # trusts what it is handed and system_admin bypasses every ACL check,
        # so this filter is the only thing between an admin's bypass and a
        # public URL.
        self.admin_roles = tuple(
            r.strip() for r in
            _env("SHARE_ADMIN_ROLES", "system_admin,tenant_admin,administrators").split(",")
            if r.strip()
        )

        self.max_ttl_days = _int("SHARE_MAX_TTL_DAYS", 30)
        # A redemption session, not an HTTP request, is what consumes a use
        # (spec §6.4) -- so this is how long Range continuations and retries
        # may keep riding one redemption_uid.
        self.session_ttl_seconds = _int("SHARE_SESSION_TTL_SECONDS", 3600)
        self.default_ttl_days = _int("SHARE_DEFAULT_TTL_DAYS", 7)
        self.max_uses_cap = _int("SHARE_MAX_USES_CAP", 100)
        self.max_recipients = _int("SHARE_MAX_RECIPIENTS", 20)
        self.upload_max_files = _int("SHARE_UPLOAD_MAX_FILES", 20)
        self.upload_max_bytes = _int("SHARE_UPLOAD_MAX_BYTES", 1024 ** 3)
        self.upload_max_file_bytes = _int("SHARE_UPLOAD_MAX_FILE_BYTES", 256 * 1024 ** 2)
        self.zip_max_members = _int("SHARE_ZIP_MAX_MEMBERS", 5000)
        self.zip_max_bytes = _int("SHARE_ZIP_MAX_BYTES", 2 * 1024 ** 3)
        self.retention_days = _int("SHARE_RETENTION_DAYS", 365)

        # Public URLs are built from this. Set it explicitly to move share
        # traffic to a separate download host later without invalidating links
        # already sent (spec §8.3).
        self.public_base_url = _env("SHARE_PUBLIC_BASE_URL", "")

        self.log_level = _env("SHARE_LOG_LEVEL", "INFO")


_config: Config | None = None


def get_config() -> Config:
    global _config
    if _config is None:
        load_dotenv()
        _config = Config()
    return _config
