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

"""share_service application entry point.

Two listeners, as every service in this platform has:

  * the **API** on ``SHARE_API_PORT`` (8101) — bearer-authenticated in M0; the
    unauthenticated public router arrives in M4 as a *separately mounted* router
    with different dependencies, never as allowlisted exceptions inside this one
    (spec §7).
  * **monitoring** on ``SHARE_MONITORING_PORT`` (8102), bound **loopback-only**.
    ``/healthz`` ``/readyz`` ``/poolz`` ``/metrics`` are unauthenticated because
    a scraper cannot present a token, so they must not be reachable off-host.
"""
from __future__ import annotations

import logging
import threading

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from . import api, core_client, db
from . import metrics as _fe_metrics
from .audit import get_emitter
from .config import Config, get_config

__version__ = "0.1.0"

log = logging.getLogger("share_service")


def create_app(config: Config) -> FastAPI:
    app = FastAPI(title="FileEngine share_service",
                  description="Outside share links — verified-recipient download & drop links",
                  version=__version__)
    app.state.config = config
    # Owner-side routes only. The unauthenticated public router (M4) mounts
    # separately, with its own dependencies -- never as exceptions inside this
    # one (spec §7).
    app.include_router(api.router)
    return app


def create_monitoring_app(config: Config) -> FastAPI:
    mon = FastAPI(title="share_service monitoring", docs_url=None, redoc_url=None)

    @mon.get("/healthz")
    def healthz():
        """Liveness: the process is up. Deliberately checks nothing else."""
        return {"status": "ok"}

    @mon.get("/readyz")
    def readyz():
        """Readiness: every hard dependency.

        Audit is a hard dependency here, unlike in most services — without it
        the fact that an access was external would go unrecorded, so the
        feature refuses to serve rather than serve unaudited (spec §4.3).
        """
        pg_ok, pg_err = db.healthy(config)
        core_ok, core_err = core_client.healthy(config)
        audit_ok = get_emitter(config).available

        checks = {
            "postgres": {"ok": pg_ok, **({"error": pg_err} if pg_err else {})},
            "core": {"ok": core_ok, **({"error": core_err} if core_err else {})},
            "audit": {"ok": audit_ok,
                      **({} if audit_ok else
                         {"error": "no audit publisher — share links disabled"})},
        }
        ready = pg_ok and core_ok and audit_ok
        return JSONResponse({"status": "ready" if ready else "not ready",
                             "checks": checks,
                             "share_enabled": config.enabled and audit_ok},
                            status_code=200 if ready else 503)

    @mon.get("/poolz")
    def poolz():
        return {"provisioned_tenants": sorted(db._provisioned)}

    # The shared collector, byte-identical across services — installs /metrics.
    _fe_metrics.install(mon, "share_service", [], {"version": __version__})

    return mon


def _serve_monitoring(config: Config) -> threading.Thread:
    mon = create_monitoring_app(config)
    server = uvicorn.Server(uvicorn.Config(
        mon, host=config.monitoring_host, port=config.monitoring_port,
        log_level=config.log_level.lower(), access_log=False))
    t = threading.Thread(target=server.run, name="share-monitoring", daemon=True)
    t.start()
    return t


def main() -> None:
    config = get_config()
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if not get_emitter(config).available:
        # Not fatal at startup — /readyz reports it and the routes refuse — but
        # it must be loud, because the failure mode it prevents (unrecorded
        # external access) is invisible from the outside.
        log.error("share_service starting WITHOUT audit: link creation and "
                  "redemption will refuse until the audit stream is reachable")

    _serve_monitoring(config)
    log.info("share_service API on %s:%d (monitoring on %s:%d)",
             config.api_host, config.api_port,
             config.monitoring_host, config.monitoring_port)

    uvicorn.run(create_app(config), host=config.api_host, port=config.api_port,
                log_level=config.log_level.lower())


if __name__ == "__main__":
    main()
