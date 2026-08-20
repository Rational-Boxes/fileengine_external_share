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

"""Test bootstrap.

``Config()`` reads the environment but does not load ``.env`` — that is
``get_config()``'s job at startup. Tests construct ``Config`` directly (so they
can override individual knobs), so the dotenv load happens once here instead.
Without it the live tests skip themselves for a missing JWT secret that is
sitting in ``.env`` all along, which looks exactly like "no dev environment".
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.normpath(os.path.join(_HERE, "..", ".."))

# Sibling checkout of the FileEngine gRPC client, mirroring how the other
# services bootstrap it when it is not pip-installed.
_PY_IFACE = os.path.normpath(os.path.join(_REPO, "..", "python_interface"))
if os.path.isdir(_PY_IFACE) and _PY_IFACE not in sys.path:
    sys.path.insert(0, _PY_IFACE)

from share_service.config import load_dotenv  # noqa: E402

load_dotenv(os.path.join(_REPO, ".env"))
