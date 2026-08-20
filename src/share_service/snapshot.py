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

"""The creation-time folder walk (spec §6.5).

**A snapshot, not a live walk.** The member set is captured when the link is
minted and served unchanged thereafter, so files dropped into the folder next
month are never included. That is the folder-scale form of version pinning: a
live folder link keeps exposing whatever lands in a shared project directory,
which is a much bigger leak than a single file's future edits.
``follow_folder = true`` opts into live semantics, and the UI labels it plainly.

The walk runs **as the creator** — it is an ordinary delegated directory
listing, so a folder they cannot read produces nothing, and members they cannot
read never enter the snapshot in the first place.

Two of the three share shapes land here and differ only in how far this
descends: ``include_subdirs = false`` takes the folder's own files,
``true`` mirrors the subtree (spec §13-R8).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

from .archive import ArchivePathError, Member, archive_length, normalize_archive_path
from .config import Config
from .core_client import DelegatedCore

log = logging.getLogger("share_service.snapshot")


class SnapshotTooLarge(ValueError):
    """The folder exceeds a deployment cap. Refused at creation, with numbers,
    so a recipient never discovers the limit mid-download (spec §6.1)."""

    def __init__(self, message: str, *, members: int, total_bytes: int):
        super().__init__(message)
        self.members = members
        self.total_bytes = total_bytes


@dataclass
class Snapshot:
    members: List[Member]
    archive_bytes: int
    skipped: List[str]          # paths omitted, with the reason, for the log

    @property
    def file_count(self) -> int:
        return sum(1 for m in self.members if not m.is_dir)

    @property
    def total_bytes(self) -> int:
        return sum(m.size_bytes for m in self.members)


def _entry_is_dir(entry) -> bool:
    """`DirectoryEntry` exposes `is_container`; `is_dir` lives on `FileInfo`.

    Asking for the wrong one returns None, which is indistinguishable from an
    empty folder — a silent, and therefore expensive, mistake.
    """
    return bool(getattr(entry, "is_container", False))


def walk(core: DelegatedCore, cfg: Config, root_uid: str, *,
         include_subdirs: bool = True) -> Snapshot:
    """Capture the folder's members as the creator.

    Raises :class:`SnapshotTooLarge` if the folder exceeds
    ``share.zip_max_members`` or ``share.zip_max_bytes``.
    """
    members: List[Member] = []
    skipped: List[str] = []
    total_bytes = 0

    # Iterative, not recursive: a deep tree should not depend on the
    # interpreter's stack limit, and a cycle in the folder graph (a corrupt
    # parent_uid) must terminate rather than recurse forever. `seen` is what
    # makes the second guarantee hold.
    seen: set[str] = set()
    queue: List[tuple[str, str]] = [(root_uid, "")]

    while queue:
        uid, prefix = queue.pop(0)
        if uid in seen:
            log.warning("snapshot: folder cycle at %s — not descending twice", uid)
            continue
        seen.add(uid)

        try:
            entries = core.client.dir(uid)
        except Exception as e:  # noqa: BLE001 - an unreadable folder is not fatal
            skipped.append(f"{prefix or '.'}: unreadable ({e})")
            continue

        children = list(entries or [])
        if not children and prefix:
            # An empty folder is emitted as a directory entry so the structure
            # survives extraction (spec §6.5).
            try:
                members.append(Member(normalize_archive_path(prefix), 0, member_uid=uid,
                                      is_dir=True))
            except ArchivePathError as e:
                skipped.append(f"{prefix}: {e}")
            continue

        for entry in children:
            name = getattr(entry, "name", "") or ""
            raw_path = f"{prefix}/{name}" if prefix else name
            if _entry_is_dir(entry):
                if include_subdirs:
                    queue.append((entry.uid, raw_path))
                continue

            try:
                path = normalize_archive_path(raw_path)
            except ArchivePathError as e:
                # A hostile or unrepresentable name is dropped, not fatal: one
                # bad file must not make a folder unshareable.
                skipped.append(f"{raw_path}: {e}")
                log.warning("snapshot: skipping %r — %s", raw_path, e)
                continue

            size = int(getattr(entry, "size", 0) or 0)
            members.append(Member(path, size, member_uid=entry.uid,
                                  version_name=str(getattr(entry, "version", "") or "")))
            total_bytes += size

            if cfg.zip_max_members and len(members) > cfg.zip_max_members:
                raise SnapshotTooLarge(
                    f"folder has more than {cfg.zip_max_members} files",
                    members=len(members), total_bytes=total_bytes)
            if cfg.zip_max_bytes and total_bytes > cfg.zip_max_bytes:
                raise SnapshotTooLarge(
                    f"folder is larger than {cfg.zip_max_bytes} bytes",
                    members=len(members), total_bytes=total_bytes)

    # Deterministic order: the archive a link produces should not depend on the
    # order the core happened to return children in.
    members.sort(key=lambda m: m.archive_path)
    return Snapshot(members=members, archive_bytes=archive_length(members),
                    skipped=skipped)


# --- persistence ----------------------------------------------------------

def store(conn, link_uid: str, snapshot: Snapshot) -> None:
    """Write the snapshot as this link's authoritative member set."""
    with conn.cursor() as cur:
        for m in snapshot.members:
            cur.execute(
                """INSERT INTO share_link_members
                     (link_uid, member_uid, archive_path, version_name, size_bytes)
                   VALUES (%s,%s,%s,%s,%s)
                   ON CONFLICT (link_uid, member_uid) DO NOTHING""",
                (link_uid, m.member_uid, m.entry_name(), m.version_name, m.size_bytes))
        cur.execute("UPDATE share_links SET archive_bytes = %s WHERE link_uid = %s",
                    (snapshot.archive_bytes, link_uid))
    conn.commit()


def load(conn, link_uid: str) -> List[Member]:
    """The stored member set — *the* source of member uids at redemption.

    Nothing a caller supplies may influence this. The core will stream any uid
    the creator can read, so this row set is the only thing confining a
    redemption to the folder it was minted for (spec §4.3).
    """
    with conn.cursor() as cur:
        cur.execute(
            """SELECT member_uid, archive_path, version_name, size_bytes
                 FROM share_link_members WHERE link_uid = %s
                ORDER BY archive_path""", (link_uid,))
        rows = cur.fetchall()
    out: List[Member] = []
    for member_uid, path, version, size in rows:
        is_dir = path.endswith("/")
        out.append(Member(path.rstrip("/") if is_dir else path, int(size),
                          member_uid=str(member_uid), version_name=version or "",
                          is_dir=is_dir))
    return out
