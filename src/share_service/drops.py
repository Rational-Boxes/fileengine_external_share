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

"""Receiving a dropped file (spec §6.7, §6.8).

The inbound half of the feature: an outside sender, verified by OTP, puts a file
into a folder they cannot otherwise see. Four rules shape it.

**A drop never creates a version of an existing file.** A colliding name gets a
de-duplicating suffix — ``report (1).pdf``. It must not be possible for an
outside sender to inject a revision into a document's history: that is a
data-integrity problem and a plausible attack, since poisoning the "latest" of a
file other people trust is more useful to an attacker than adding a new one.

**The file slot is reserved before any bytes are stored, and released if the
store fails.** So a dropped connection costs the sender nothing, and two
concurrent drops cannot both take the last slot.

**Dropped files are owned by the link's creator**, so inherited ACLs behave
exactly as if they had uploaded them and no orphan principal appears in the ACL
tables. The outside origin is recorded in metadata and audit instead (§6.8).

**The extension allowlist is a convenience, never a security control.** It is
matched on the claimed name only; content type is not trusted and nothing is
executed.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import List, Optional

from .config import Config
from .core_client import DelegatedCore

log = logging.getLogger("share_service.drops")

# The Python core client sends a file in ONE PutFile message (it does not expose
# StreamFileUpload), and its channel is configured for 64 MiB. So that is the
# real per-file ceiling regardless of what a link's budget says. Lifting it means
# exposing the streaming RPC in python_interface, not raising a number here.
GRPC_MESSAGE_CEILING = 64 * 1024 * 1024

_UNSAFE_NAME = re.compile(r"[\x00-\x1f/\\]")


class DropRefused(ValueError):
    """The drop cannot be accepted. ``reason`` is for audit, not for the sender."""

    def __init__(self, reason: str, message: str = ""):
        super().__init__(message or reason)
        self.reason = reason


@dataclass
class DropResult:
    file_uid: str
    stored_name: str
    size_bytes: int


def safe_filename(raw: str) -> str:
    """One path segment, with nothing that could steer where it lands.

    The sender chooses this string, so it is stripped to a bare name: separators
    and control characters removed, leading dots refused (no ``.hidden`` or
    ``..``), and length bounded. A name is not a path here — the destination
    comes from the link record, never from the sender (spec §4.3).
    """
    name = _UNSAFE_NAME.sub("", (raw or "").strip())
    name = name.lstrip(". ").strip()
    if not name:
        raise DropRefused("bad_filename", "a file name is required")
    if len(name) > 200:
        stem, ext = os.path.splitext(name)
        name = stem[:200 - len(ext)] + ext
    return name


def extension_allowed(name: str, allowlist: Optional[List[str]]) -> bool:
    """Convenience for the sender, never a security control (spec §6.7)."""
    if not allowlist:
        return True
    ext = os.path.splitext(name)[1].lower().lstrip(".")
    return ext in {e.lower().lstrip(".") for e in allowlist}


def effective_file_cap(cfg: Config, link_max_file_bytes: int) -> int:
    caps = [c for c in (link_max_file_bytes, cfg.upload_max_file_bytes,
                        GRPC_MESSAGE_CEILING) if c]
    return min(caps) if caps else GRPC_MESSAGE_CEILING


# --- budget ---------------------------------------------------------------

def reserve_slot(conn, link_uid: str) -> bool:
    """Take one file slot, atomically. False when the budget is spent.

    Reserved *before* the bytes are read so an exhausted link fails fast, and so
    two concurrent drops cannot both take the last slot — the conditional UPDATE
    is what makes that true, not the check that precedes it.
    """
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE share_links
                  SET files_consumed = files_consumed + 1
                WHERE link_uid = %s
                  AND revoked_at IS NULL AND expires_at > now()
                  AND (max_files = 0 OR files_consumed < max_files)""",
            (link_uid,))
        took = cur.rowcount > 0
    conn.commit()
    return took


def release_slot(conn, link_uid: str) -> None:
    """Give the slot back after a failed store, so an aborted upload costs the
    sender nothing. Floored at zero: a double release must not manufacture
    budget."""
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE share_links
                  SET files_consumed = GREATEST(files_consumed - 1, 0)
                WHERE link_uid = %s""",
            (link_uid,))
    conn.commit()


def remaining_bytes(link) -> Optional[int]:
    if not link.max_bytes:
        return None
    return max(0, link.max_bytes - link.bytes_consumed)


# --- placement ------------------------------------------------------------

def _children(core: DelegatedCore, folder_uid: str):
    try:
        return list(core.client.dir(folder_uid) or [])
    except Exception:  # noqa: BLE001
        return []


def resolve_landing_folder(core: DelegatedCore, folder_uid: str,
                           landing_prefix: Optional[str]) -> str:
    """The folder a drop lands in — the target, or a lazily created subfolder.

    For deployments that want outside drops quarantined from the folder proper
    (spec §6.7). Created as the creator, so it inherits the same ACLs.
    """
    if not landing_prefix:
        return folder_uid
    wanted = safe_filename(landing_prefix)
    for entry in _children(core, folder_uid):
        if getattr(entry, "is_container", False) and getattr(entry, "name", "") == wanted:
            return entry.uid
    made = core.client.mkdir(folder_uid, wanted)
    return getattr(made, "uid", made)


def unique_name(core: DelegatedCore, folder_uid: str, name: str) -> str:
    """``report.pdf`` -> ``report (1).pdf`` when the name is taken.

    A drop never versions an existing file (spec §6.7), so a collision has to
    become a new name rather than a new revision.
    """
    taken = {getattr(e, "name", "") for e in _children(core, folder_uid)}
    if name not in taken:
        return name
    stem, ext = os.path.splitext(name)
    for n in range(1, 1000):
        candidate = f"{stem} ({n}){ext}"
        if candidate not in taken:
            return candidate
    raise DropRefused("too_many_collisions",
                      "too many files with this name already")


# --- the drop -------------------------------------------------------------

def store(core: DelegatedCore, *, folder_uid: str, name: str, payload: bytes,
          landing_prefix: Optional[str], provenance: dict) -> DropResult:
    """Create the file as the creator and stamp its origin.

    Provenance is written as **version** metadata on the dropped version and
    mirrored to file metadata (spec §6.8): drops never version an existing file,
    but an internal user may add a version later, at which point file-level
    metadata would be describing bytes the sender never sent.

    These keys are a convenience copy, not evidence — the core does not reserve
    the `share.*` namespace, so anyone with WRITE can rewrite them. The
    authoritative record is the redemption row and the audit chain (§13-R13).
    """
    target = resolve_landing_folder(core, folder_uid, landing_prefix)
    stored_name = unique_name(core, target, name)

    file_uid = core.client.touch(target, stored_name)
    file_uid = getattr(file_uid, "uid", file_uid)
    core.client.put(file_uid, payload)

    version = ""
    try:
        version = core.current_version(file_uid)
    except Exception:  # noqa: BLE001 - provenance is best-effort, the file is not
        pass

    for key, value in provenance.items():
        if value is None:
            continue
        try:
            core.client.set_metadata_value(file_uid, key, str(value))
        except Exception:  # noqa: BLE001
            log.warning("could not stamp %s on %s", key, file_uid)
    if version:
        # Recorded so a later revision cannot inherit the sender's attribution.
        try:
            core.client.set_metadata_value(file_uid, "share.version", version)
        except Exception:  # noqa: BLE001
            pass

    return DropResult(file_uid=str(file_uid), stored_name=stored_name,
                      size_bytes=len(payload))
