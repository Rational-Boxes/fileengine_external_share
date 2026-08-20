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

"""The archive arithmetic and the store-only zip64 writer (M1).

The load-bearing test is :func:`test_declared_length_matches_produced_bytes`:
``archive_bytes`` is computed at creation from names and sizes alone and served
as a real ``Content-Length``, so if the arithmetic is off by even one byte per
entry every folder download is a corrupt archive. The term most easily missed
is the 24-byte zip64 data descriptor, which exists only because streaming
defers the CRC (spec §6.5).

Verifying with ``zipfile`` is not enough on its own — it is lenient about
trailing bytes — so the byte count is compared directly *and* the archive is
round-tripped through a real reader that validates CRCs.
"""
from __future__ import annotations

import io
import zipfile

import pytest

from share_service.archive import (
    ArchiveLengthMismatch, ArchivePathError, Member, archive_length,
    normalize_archive_path, stream,
)


def _payload(size: int) -> bytes:
    return (bytes(range(256)) * (size // 256 + 1))[:size]


def _write(members, chunk_size: int = 1024) -> bytes:
    data = {m.archive_path: _payload(m.size_bytes) for m in members if not m.is_dir}

    def opener(m):
        raw = data[m.archive_path]
        if not raw:
            return
        for i in range(0, len(raw), chunk_size):
            yield raw[i:i + chunk_size]

    return b"".join(stream(members, opener))


# --- the arithmetic -------------------------------------------------------

@pytest.mark.parametrize("members", [
    pytest.param([Member("a.txt", 11)], id="single-file"),
    pytest.param([Member("a.txt", 0)], id="empty-file"),
    pytest.param([Member("d", 0, is_dir=True)], id="only-a-directory"),
    pytest.param([Member("a.txt", 11), Member("d/b.bin", 4096),
                  Member("d/empty", 0, is_dir=True), Member("d/deep/c.dat", 1)],
                 id="mixed-tree"),
    pytest.param([Member("ünïcödé-ファイル.txt", 7)], id="non-ascii-name"),
    pytest.param([Member(f"f{i:04d}.bin", i) for i in range(200)], id="200-members"),
])
def test_declared_length_matches_produced_bytes(members):
    assert archive_length(members) == len(_write(members))


def test_length_is_independent_of_chunking():
    """The declared length must not depend on how the source yields bytes —
    otherwise a slow network could change the Content-Length."""
    members = [Member("a.bin", 5000), Member("b.bin", 3)]
    declared = archive_length(members)
    for chunk in (1, 7, 512, 4096, 100000):
        assert len(_write(members, chunk_size=chunk)) == declared


def test_the_data_descriptor_term_is_not_optional():
    """Guards the specific mistake: omitting the descriptor under-counts by
    exactly 24 bytes per file entry, which reads as 'nearly right'."""
    members = [Member("a.txt", 10), Member("b.txt", 20), Member("c.txt", 30)]
    naive = archive_length(members) - 24 * len(members)
    assert naive != len(_write(members))
    assert len(_write(members)) - naive == 24 * len(members)


# --- real readers ---------------------------------------------------------

def test_zipfile_reads_it_and_verifies_crcs():
    members = [Member("a.txt", 11), Member("d/b.bin", 4096),
               Member("d/empty", 0, is_dir=True)]
    raw = _write(members)
    zf = zipfile.ZipFile(io.BytesIO(raw))
    assert zf.testzip() is None          # validates every CRC
    assert zf.read("a.txt") == _payload(11)
    assert zf.read("d/b.bin") == _payload(4096)


def test_directory_entries_survive():
    """Empty folders are emitted so the structure survives extraction."""
    members = [Member("keep/me", 0, is_dir=True), Member("a.txt", 1)]
    names = zipfile.ZipFile(io.BytesIO(_write(members))).namelist()
    assert "keep/me/" in names            # a zip marks directories with a slash


def test_non_ascii_names_round_trip():
    members = [Member("ünïcödé-ファイル.txt", 7)]
    zf = zipfile.ZipFile(io.BytesIO(_write(members)))
    assert zf.namelist() == ["ünïcödé-ファイル.txt"]
    assert zf.read("ünïcödé-ファイル.txt") == _payload(7)


# --- the size-mismatch abort ---------------------------------------------

def test_a_short_member_aborts_rather_than_truncating():
    """A declared Content-Length is already on the wire by now, so a short body
    is a silently corrupt archive. Failing loudly is the honest option."""
    members = [Member("a.bin", 100)]

    def short(_m):
        yield b"x" * 40

    with pytest.raises(ArchiveLengthMismatch):
        b"".join(stream(members, short))


def test_an_overlong_member_aborts_too():
    members = [Member("a.bin", 10)]

    def long(_m):
        yield b"x" * 50

    with pytest.raises(ArchiveLengthMismatch):
        b"".join(stream(members, long))


# --- path safety (zip-slip) ----------------------------------------------

@pytest.mark.parametrize("bad", [
    "../escape.txt", "a/../../escape.txt", "/absolute.txt", "//unc/share/x",
    "C:/windows/system32", "..", "", "   ", "./", "a/\x00b",
])
def test_hostile_paths_are_refused(bad):
    with pytest.raises(ArchivePathError):
        normalize_archive_path(bad)


@pytest.mark.parametrize("raw,expected", [
    ("a.txt", "a.txt"),
    ("./a.txt", "a.txt"),
    ("d//b.txt", "d/b.txt"),
    ("d/./b.txt", "d/b.txt"),
    ("d\\b.txt", "d/b.txt"),          # a Windows-style name is normalized...
    ("  spaced.txt  ", "spaced.txt"),
    ("a/b/c/d.txt", "a/b/c/d.txt"),
])
def test_ordinary_paths_normalize(raw, expected):
    assert normalize_archive_path(raw) == expected


def test_backslash_traversal_is_still_traversal():
    """...which means backslash forms must be checked *after* normalization,
    or `..\\..\\etc` walks straight past a naive `..` check."""
    with pytest.raises(ArchivePathError):
        normalize_archive_path("..\\..\\etc\\passwd")
