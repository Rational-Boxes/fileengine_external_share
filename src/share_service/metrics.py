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

"""Prometheus exposition for a FileEngine service.

**This file is copied verbatim between services**, the same way
``fileservice.proto`` is. Keep the copies identical; per-service metrics belong
in the caller's ``collect`` callback, not in here.

**Why hand-rolled rather than ``prometheus_client``.** The exposition format is
a few lines of text, and every service in this platform would otherwise gain a
dependency it does not have today — eight requirements files, eight container
rebuilds — for something that has to work identically in dev and prod on day
one. What ``prometheus_client`` would give for free is the ``process_*`` family,
so that is reproduced here from ``/proc``, including the per-thread state that a
plain thread count cannot express.

The names follow the conventions tooling depends on: one ``fileengine_``
namespace with a ``service`` label, base units (seconds and bytes, never
milliseconds), ``_total`` on monotonic counters, and HELP/TYPE on every family.
That is what lets Prometheus, the OpenTelemetry collector, Grafana Agent and
load-balancer autoscalers read this without a bespoke adapter.
"""
from __future__ import annotations

import os
import time
from typing import Callable, Iterable, Mapping, Sequence

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

_STARTED = time.time()


def _fmt(value: float) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.6g}"


def _labels(pairs: Mapping[str, str] | None) -> str:
    if not pairs:
        return ""
    out = []
    for key, raw in pairs.items():
        v = str(raw).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        out.append(f'{key}="{v}"')
    return "{" + ",".join(out) + "}"


class Metrics:
    """Accumulates families and renders them in exposition order."""

    def __init__(self, service: str) -> None:
        self.service = service
        self._lines: list[str] = []
        self._declared: set[str] = set()

    def family(self, name: str, help_text: str, kind: str) -> None:
        if name in self._declared:
            return
        self._declared.add(name)
        self._lines.append(f"# HELP {name} {help_text}")
        self._lines.append(f"# TYPE {name} {kind}")

    def sample(self, name: str, value: float, labels: Mapping[str, str] | None = None) -> None:
        merged = {"service": self.service}
        if labels:
            merged.update(labels)
        self._lines.append(f"{name}{_labels(merged)} {_fmt(value)}")

    def gauge(self, name: str, help_text: str, value: float,
              labels: Mapping[str, str] | None = None) -> None:
        self.family(name, help_text, "gauge")
        self.sample(name, value, labels)

    def counter(self, name: str, help_text: str, value: float,
                labels: Mapping[str, str] | None = None) -> None:
        self.family(name, help_text, "counter")
        self.sample(name, value, labels)

    def render(self) -> str:
        return "\n".join(self._lines) + "\n"


def _read_proc_status() -> dict[str, str]:
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as fh:
            out = {}
            for line in fh:
                key, _, value = line.partition(":")
                out[key.strip()] = value.strip()
            return out
    except OSError:
        return {}


def _thread_states() -> dict[str, int]:
    """Per-thread kernel state, which a bare thread count cannot express.

    ``R`` is work in progress and ``D`` is blocked in the kernel on I/O and
    cannot be interrupted or timed out — the one to alarm on. Everything else
    parked in ``S`` is a healthy idle worker, so a large total is not by itself a
    problem.
    """
    counts = {"running": 0, "sleeping": 0, "uninterruptible": 0,
              "stopped": 0, "zombie": 0, "other": 0}
    try:
        for tid in os.listdir("/proc/self/task"):
            try:
                with open(f"/proc/self/task/{tid}/stat", "r", encoding="utf-8") as fh:
                    line = fh.read()
            except OSError:
                continue  # a thread can exit between listing and opening
            # Field 3, but field 2 is the command name in parentheses and may
            # itself contain spaces and parentheses — scan from the LAST ')'.
            close = line.rfind(")")
            if close < 0:
                continue
            rest = line[close + 1:].lstrip()
            if not rest:
                continue
            state = rest[0]
            if state == "R":
                counts["running"] += 1
            elif state == "S":
                counts["sleeping"] += 1
            elif state == "D":
                counts["uninterruptible"] += 1
            elif state in ("T", "t"):
                counts["stopped"] += 1
            elif state == "Z":
                counts["zombie"] += 1
            else:
                counts["other"] += 1
    except OSError:
        return {}
    return counts


def process_metrics(m: Metrics) -> None:
    """The ``process_*`` family, reproduced from /proc.

    Standard names, because dashboards and alerts for them already exist.
    """
    status = _read_proc_status()

    if "VmRSS" in status:
        kb = status["VmRSS"].split()[0]
        try:
            m.gauge("process_resident_memory_bytes",
                    "Resident memory size in bytes", int(kb) * 1024)
        except ValueError:
            pass

    try:
        m.gauge("process_open_fds", "Open file descriptors",
                len(os.listdir("/proc/self/fd")))
    except OSError:
        pass

    states = _thread_states()
    if states:
        total = sum(states.values())
        m.gauge("process_threads", "Threads in this process", total)
        m.family("fileengine_threads",
                 "Threads by kernel state. `uninterruptible` is blocked in the kernel and "
                 "cannot be cancelled; a healthy idle service holds everything in `sleeping`",
                 "gauge")
        for state, count in states.items():
            m.sample("fileengine_threads", count, {"state": state})
        m.gauge("fileengine_threads_not_waiting",
                "Threads not in interruptible sleep. An idle service should hold this near zero",
                total - states.get("sleeping", 0))

    m.gauge("fileengine_uptime_seconds", "Seconds since this process started serving",
            time.time() - _STARTED)


def render(service: str,
           collectors: Sequence[Callable[[Metrics], None]] = (),
           build: Mapping[str, str] | None = None) -> str:
    """Render the full exposition for one service.

    ``collectors`` are the service's own metrics; each is called with the
    ``Metrics`` accumulator and may fail independently — a broken collector must
    degrade the scrape, not fail it, because metrics that vanish exactly when
    something goes wrong are metrics you cannot alert on.
    """
    m = Metrics(service)
    m.gauge("fileengine_build_info", "Build identity; the value is always 1", 1, build or {})
    try:
        process_metrics(m)
    except Exception:  # noqa: BLE001 - never fail a scrape over process stats
        pass
    for collect in collectors:
        try:
            collect(m)
        except Exception:  # noqa: BLE001 - one bad collector must not blank the rest
            m.gauge("fileengine_collector_failed",
                    "1 when a metrics collector raised during this scrape", 1,
                    {"collector": getattr(collect, "__name__", "unknown")})
    return m.render()


def install(app, service: str,
            collectors: Iterable[Callable[[Metrics], None]] = (),
            build: Mapping[str, str] | None = None,
            path: str = "/metrics") -> None:
    """Add the scrape endpoint to a FastAPI app.

    Unauthenticated like the other monitoring routes, and expected to be bound
    loopback-only or behind the same IP allowlist for the same reason.
    """
    from fastapi.responses import PlainTextResponse

    collectors = list(collectors)

    @app.get(path, response_class=PlainTextResponse, include_in_schema=False)
    def metrics() -> PlainTextResponse:  # pragma: no cover - exercised via TestClient
        return PlainTextResponse(render(service, collectors, build),
                                 media_type=CONTENT_TYPE)
