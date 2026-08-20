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

"""Store-only zip64 framing, with an exactly computable length (spec §6.5).

Two things have to be true at once, and they pull against each other:

* the archive must be **streamed** — nothing buffered to disk or memory beyond
  one chunk, because a folder link can be gigabytes; and
* its byte length must be **known before the first byte goes out**, so the
  recipient gets a real ``Content-Length`` and a progress bar instead of an
  indefinite chunked transfer, and so a deployment can budget egress exactly.

Store-only (``method 0``) gets most of the way: with no compressor, an entry's
payload length is its file size. The obstacle is the CRC-32, which a local file
header carries *before* the data — and which is only known once the bytes have
been read. The core stores no per-version digest to look it up from
(``versions`` holds size and storage_path, no checksum), and computing CRCs at
creation would mean reading every byte of the folder while the creator waits in
a drawer.

So every entry sets **general-purpose bit 3** and defers its CRC and sizes to a
**zip64 data descriptor** written after the payload. That descriptor is a fixed
24 bytes, so the total stays exactly computable — it simply has a term that a
naive calculation omits, which is the single easiest way to ship an archive
whose declared length does not match its body.

The one cost is compatibility: bit 3 is what every "download as zip" on the web
produces and every mainstream extractor handles, but some older Windows-native
paths and embedded tools dislike data descriptors. ``share.zip_deflate`` exists
for anyone who would rather trade the exact length away.
"""
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, List

# --- fixed sizes, named so the arithmetic below reads as the spec does -----
LOCAL_HEADER = 30           # signature .. extra length
LOCAL_ZIP64_EXTRA = 20      # id 2 + size 2 + uncompressed 8 + compressed 8
DATA_DESCRIPTOR = 24        # signature 4 + crc 4 + compressed 8 + uncompressed 8
CENTRAL_HEADER = 46         # signature .. relative offset
CENTRAL_ZIP64_EXTRA = 28    # id 2 + size 2 + uncompressed 8 + compressed 8 + offset 8
ZIP64_EOCD = 56
ZIP64_EOCD_LOCATOR = 20
EOCD = 22

_SIG_LOCAL = 0x04034B50
_SIG_DESCRIPTOR = 0x08074B50
_SIG_CENTRAL = 0x02014B50
_SIG_ZIP64_EOCD = 0x06064B50
_SIG_ZIP64_LOCATOR = 0x07064B50
_SIG_EOCD = 0x06054B50

_FLAG_DATA_DESCRIPTOR = 0x0008
_FLAG_UTF8 = 0x0800
_METHOD_STORE = 0
_VERSION_ZIP64 = 45         # 4.5 — the minimum that understands zip64

# A fixed DOS timestamp. Member mtimes are deliberately not used: they would
# make `archive_bytes` depend on metadata that can change between the creation
# walk and the stream, and a zip's declared length must not be able to drift.
_DOS_TIME = 0
_DOS_DATE = 0x21            # 1980-01-01, the DOS epoch


class ArchivePathError(ValueError):
    """A member path that must never reach a recipient's extractor."""


def normalize_archive_path(raw: str) -> str:
    """Validate and normalize a path for use inside the archive (spec §5.2).

    Rejects anything that could escape the extraction directory — the zip-slip
    class. This runs at *creation*, so a hostile name is refused while an
    authenticated user is watching, not while a recipient is unpacking.
    """
    if raw is None:
        raise ArchivePathError("empty archive path")
    path = raw.replace("\\", "/").strip()
    if not path:
        raise ArchivePathError("empty archive path")
    if path.startswith("/"):
        raise ArchivePathError(f"absolute path: {raw!r}")
    # Windows drive letters and UNC paths are absolute too, in a form that a
    # leading-slash check misses entirely.
    if len(path) > 1 and path[1] == ":":
        raise ArchivePathError(f"drive-qualified path: {raw!r}")
    if path.startswith("//"):
        raise ArchivePathError(f"UNC path: {raw!r}")

    parts: List[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue          # collapse doubled and trailing separators
        if part == "..":
            raise ArchivePathError(f"parent traversal in {raw!r}")
        if "\x00" in part:
            raise ArchivePathError(f"NUL in {raw!r}")
        parts.append(part)
    if not parts:
        raise ArchivePathError(f"path resolves to nothing: {raw!r}")
    return "/".join(parts)


@dataclass
class Member:
    """One entry in the archive.

    ``size_bytes`` is pinned at creation, alongside the version it came from —
    which is what lets the length be computed before anything is read.
    """
    archive_path: str
    size_bytes: int
    member_uid: str = ""
    version_name: str = ""
    is_dir: bool = False

    def entry_name(self) -> str:
        """Directory entries carry a trailing slash; that is how a zip marks
        them, and it costs one byte that the arithmetic must include."""
        return self.archive_path + "/" if self.is_dir else self.archive_path


def entry_size(member: Member) -> int:
    """Bytes this member contributes to the stream (header + payload + descriptor)."""
    name_len = len(member.entry_name().encode("utf-8"))
    if member.is_dir:
        # A directory entry has no payload and no data descriptor: there are no
        # bytes to checksum, so nothing has to be deferred.
        return LOCAL_HEADER + name_len + LOCAL_ZIP64_EXTRA
    return (LOCAL_HEADER + name_len + LOCAL_ZIP64_EXTRA
            + member.size_bytes
            + DATA_DESCRIPTOR)


def central_size(member: Member) -> int:
    """Bytes this member contributes to the central directory."""
    name_len = len(member.entry_name().encode("utf-8"))
    return CENTRAL_HEADER + name_len + CENTRAL_ZIP64_EXTRA


def archive_length(members: Iterable[Member]) -> int:
    """The exact byte length of the archive these members produce.

    Every term comes from names and sizes alone — nothing is read — which is
    what keeps ``archive_bytes`` honest between the creation walk and the
    stream (spec §6.5).
    """
    members = list(members)
    total = sum(entry_size(m) for m in members)
    total += sum(central_size(m) for m in members)
    total += ZIP64_EOCD + ZIP64_EOCD_LOCATOR + EOCD
    return total


# --- the writer -----------------------------------------------------------

def _local_header(member: Member) -> bytes:
    name = member.entry_name().encode("utf-8")
    flags = _FLAG_UTF8 | (0 if member.is_dir else _FLAG_DATA_DESCRIPTOR)
    header = struct.pack(
        "<IHHHHHIIIHH",
        _SIG_LOCAL, _VERSION_ZIP64, flags, _METHOD_STORE, _DOS_TIME, _DOS_DATE,
        0,              # crc-32: deferred to the data descriptor
        0xFFFFFFFF,     # compressed size: see zip64 extra
        0xFFFFFFFF,     # uncompressed size: see zip64 extra
        len(name), LOCAL_ZIP64_EXTRA)
    size = 0 if member.is_dir else member.size_bytes
    extra = struct.pack("<HHQQ", 0x0001, 16, size, size)
    return header + name + extra


def _data_descriptor(crc: int, size: int) -> bytes:
    return struct.pack("<IIQQ", _SIG_DESCRIPTOR, crc & 0xFFFFFFFF, size, size)


def _central_entry(member: Member, crc: int, offset: int) -> bytes:
    name = member.entry_name().encode("utf-8")
    flags = _FLAG_UTF8 | (0 if member.is_dir else _FLAG_DATA_DESCRIPTOR)
    size = 0 if member.is_dir else member.size_bytes
    # External attributes: mark directories as such so extractors create them.
    ext_attrs = 0x10 if member.is_dir else 0
    header = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        _SIG_CENTRAL, _VERSION_ZIP64, _VERSION_ZIP64, flags, _METHOD_STORE,
        _DOS_TIME, _DOS_DATE, crc & 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF,          # sizes -> zip64 extra
        len(name), CENTRAL_ZIP64_EXTRA, 0,
        0, 0, ext_attrs,
        0xFFFFFFFF)                       # local header offset -> zip64 extra
    extra = struct.pack("<HHQQQ", 0x0001, 24, size, size, offset)
    return header + name + extra


def _end_records(count: int, central_offset: int, central_len: int) -> bytes:
    z64 = struct.pack("<IQHHIIQQQQ",
                      _SIG_ZIP64_EOCD, 44, _VERSION_ZIP64, _VERSION_ZIP64,
                      0, 0, count, count, central_len, central_offset)
    locator = struct.pack("<IIQI", _SIG_ZIP64_LOCATOR, 0,
                          central_offset + central_len, 1)
    eocd = struct.pack("<IHHHHIIH", _SIG_EOCD, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                       0xFFFFFFFF, 0xFFFFFFFF, 0)
    return z64 + locator + eocd


class ArchiveLengthMismatch(RuntimeError):
    """A member produced a different number of bytes than its pinned size.

    The declared ``Content-Length`` is already on the wire by the time this can
    be detected, so the only honest response is to abort the connection: a
    short body under a declared length is a silently corrupt archive, and a
    broken transfer is at least visibly broken (spec §6.5).
    """


def stream(members: Iterable[Member],
           open_member: Callable[[Member], Iterable[bytes]]) -> Iterator[bytes]:
    """Yield the archive, one chunk at a time.

    ``open_member`` returns an iterable of byte chunks for a member — in
    production a delegated ``StreamFileDownload``. Nothing is buffered beyond
    the chunk in hand, and the CRC is computed as the bytes pass through.

    Raises :class:`ArchiveLengthMismatch` if a member's real length differs
    from the size pinned at creation.
    """
    members = list(members)
    offsets: List[int] = []
    crcs: List[int] = []
    position = 0

    for member in members:
        offsets.append(position)
        header = _local_header(member)
        yield header
        position += len(header)

        if member.is_dir:
            crcs.append(0)
            continue

        crc = 0
        written = 0
        for chunk in open_member(member):
            if not chunk:
                continue
            crc = zlib.crc32(chunk, crc)
            written += len(chunk)
            if written > member.size_bytes:
                raise ArchiveLengthMismatch(
                    f"{member.archive_path}: more bytes than the pinned "
                    f"{member.size_bytes}")
            yield chunk
        if written != member.size_bytes:
            raise ArchiveLengthMismatch(
                f"{member.archive_path}: {written} bytes, pinned "
                f"{member.size_bytes}")
        position += written

        descriptor = _data_descriptor(crc, member.size_bytes)
        yield descriptor
        position += len(descriptor)
        crcs.append(crc)

    central_offset = position
    central = b"".join(_central_entry(m, crcs[i], offsets[i])
                       for i, m in enumerate(members))
    yield central
    yield _end_records(len(members), central_offset, len(central))
