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

"""Postgres access — per-tenant schema isolation (mirrors folder_actions/CSAI).

Connections set ``search_path`` to the tenant's schema so queries are unqualified
and one tenant's rows are unreachable from another's session.
"""
from __future__ import annotations

import logging
from typing import Optional

import psycopg

from .config import Config
from .schema import ensure_tenant_schema, schema_name

log = logging.getLogger("share_service.db")


def _dsn(config: Config, readonly: bool = False) -> str:
    host = config.pg_replica_host if (readonly and config.pg_replica_host) else config.pg_host
    port = config.pg_replica_port if (readonly and config.pg_replica_host) else config.pg_port
    return (f"host={host} port={port} dbname={config.pg_database} "
            f"user={config.pg_user} password={config.pg_password}")


def connect(config: Config, readonly: bool = False):
    """A plain connection with no schema bound (DDL / cross-tenant admin)."""
    return psycopg.connect(_dsn(config, readonly))


# Tenants whose schema has been ensured in this process.
_provisioned: set[str] = set()


def provision_tenant(config: Config, tenant: str) -> str:
    """Ensure the tenant's schema + tables exist (idempotent)."""
    with connect(config) as conn:
        name = ensure_tenant_schema(conn, tenant)
    _provisioned.add(tenant)
    return name


def connect_for_tenant(config: Config, tenant: str, provision: bool = False,
                       readonly: bool = False):
    """A connection whose ``search_path`` is the tenant's schema, then public.

    The schema is ensured on the first connection to a tenant in this process.
    A read-only connection never runs DDL — it may be pointed at a replica that
    cannot write, and the primary keeps the schema in sync.
    """
    conn = psycopg.connect(_dsn(config, readonly))
    if provision and not readonly and tenant not in _provisioned:
        name = ensure_tenant_schema(conn, tenant)
        _provisioned.add(tenant)
    else:
        name = schema_name(tenant)
    with conn.cursor() as cur:
        cur.execute(f'SET search_path TO "{name}", public')
    return conn


def healthy(config: Config) -> tuple[bool, Optional[str]]:
    """(ok, error) — used by /readyz."""
    try:
        with connect(config) as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return True, None
    except Exception as e:  # pragma: no cover - exercised by @live tests
        return False, str(e)
