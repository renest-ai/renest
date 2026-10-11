"""Is a file inside a code folder code, or a model / data payload riding along?

A code archive travels under the code's own licence, and the server never holds one
back from a hand-off. So anything in a code folder that is not plausibly code (or its
small config, text and web assets) must leave the archive and travel as a ``files[]``
entry of its own, where it gets a licence lookup by sha256 -- and is restricted when
nothing vouches for it.

The first cut of this (0.1.21) decided by file name alone: the weight suffixes the
integrity probe knows. A plugin that saves its model as ``.pkl``, ``.npy``, ``.h5``,
``.msgpack``, a ``.zip``, or a file with no extension at all slipped straight past it.
This module decides by **content**, with the name only ever adding to the verdict:

1. A known weight suffix (``integrity.WEIGHT_SUFFIXES``) is a payload at any size, as
   before.
2. A serialised-data or archive container, recognised by its first bytes, is a
   payload from ``CONTAINER_MIN_BYTES`` (64 KiB) up: pickle (protocol 2-5, which is
   also what a bare ``torch.save`` writes), zip (a ``torch.save`` since 1.6, ``.npz``,
   any packed model folder), safetensors, GGUF, HDF5 (Keras ``.h5``), NumPy ``.npy``,
   TFLite, and gzip / xz / bzip2 / zstd / 7z / rar / tar. A zip that is a Python or
   Java code package (it holds a ``.dist-info/WHEEL``, ``EGG-INFO/`` or
   ``META-INF/MANIFEST.MF``) and no weight inside stays code.
3. Any other file of ``UNKNOWN_BINARY_MIN_BYTES`` (1 MiB) or more that is not text
   and not a recognised code or media format is a payload: a protobuf graph
   (``.pb``, an ONNX without its suffix), a msgpack checkpoint, a SentencePiece
   ``.model``, raw float arrays. Recognised code and media formats that stay: native
   libraries (ELF, Mach-O, PE), WebAssembly, images, fonts, audio, video, PDF and
   SQLite.

What stays in the archive on purpose: text of any size (source, JSON, YAML, vocab
files), small containers under 64 KiB (index pickles, tiny lookup tables), small
unrecognised binaries under 1 MiB, and icons, fonts and web assets of any size.

Known limits, said rather than hidden: a weight written as text (a protocol-0 pickle,
base64 inside JSON) or a weight disguised as an image is not caught; neither is a
deliberately hand-crafted file. The rule is meant to catch what plugins really do --
download a model into their own folder on first run -- not an adversary.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from .integrity import WEIGHT_SUFFIXES

__all__ = [
    "CONTAINER_MIN_BYTES",
    "UNKNOWN_BINARY_MIN_BYTES",
    "payload_kind",
]

#: From this size up, a recognised serialised-data or archive container is a payload.
CONTAINER_MIN_BYTES = 64 << 10
#: From this size up, any binary that is not a recognised code or media format is one.
UNKNOWN_BINARY_MIN_BYTES = 1 << 20

_HEAD_BYTES = 8192

#: (offset, magic, what it is) -- serialised data and archives.
_CONTAINERS: tuple[tuple[int, bytes, str], ...] = (
    (0, b"GGUF", "a GGUF model"),
    (0, b"\x89HDF\r\n\x1a\n", "an HDF5 data file"),
    (0, b"\x93NUMPY", "a NumPy array"),
    (4, b"TFL3", "a TFLite model"),
    (0, b"\x1f\x8b", "a gzip archive"),
    (0, b"\xfd7zXZ\x00", "an xz archive"),
    (0, b"BZh", "a bzip2 archive"),
    (0, b"\x28\xb5\x2f\xfd", "a zstd archive"),
    (0, b"7z\xbc\xaf\x27\x1c", "a 7z archive"),
    (0, b"Rar!\x1a\x07", "a rar archive"),
    (257, b"ustar", "a tar archive"),
)

#: (offset, magic) -- code and media formats that stay with the code at any size.
_CODE_OR_MEDIA: tuple[tuple[int, bytes], ...] = (
    (0, b"\x7fELF"), (0, b"\xfe\xed\xfa\xce"), (0, b"\xfe\xed\xfa\xcf"),
    (0, b"\xce\xfa\xed\xfe"), (0, b"\xcf\xfa\xed\xfe"), (0, b"\xca\xfe\xba\xbe"),
    (0, b"MZ"), (0, b"\x00asm"),
    (0, b"\x89PNG"), (0, b"\xff\xd8\xff"), (0, b"GIF8"), (0, b"BM"), (0, b"II*\x00"),
    (0, b"MM\x00*"), (0, b"\x00\x00\x01\x00"), (0, b"8BPS"), (0, b"RIFF"), (4, b"ftyp"),
    (0, b"\x1a\x45\xdf\xa3"), (0, b"OggS"), (0, b"fLaC"), (0, b"ID3"), (0, b"\xff\xfb"),
    (0, b"\xff\xf3"), (0, b"\xff\xf2"), (0, b"%PDF"),
    (0, b"\x00\x01\x00\x00"), (0, b"OTTO"), (0, b"wOFF"), (0, b"wOF2"), (0, b"true"),
    (0, b"ttcf"), (0, b"SQLite format 3\x00"),
)

_CODE_PACKAGE_MARKERS = (".dist-info/WHEEL", "EGG-INFO/", "META-INF/MANIFEST.MF")


def _is_text(head: bytes) -> bool:
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as e:
        # A read cut through a multi-byte character is still text.
        return e.start >= len(head) - 3
    return True


def _zip_verdict(path: Path) -> str | None:
    """A zip is a payload unless it is a code package with no weight inside."""
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError, ValueError):
        return "a zip archive"
    weighty = any(Path(n).suffix.lower() in WEIGHT_SUFFIXES
                  or n.endswith((".pkl", "/data.pkl", ".npy", ".npz", ".h5"))
                  for n in names)
    if not weighty and any(m in n for n in names for m in _CODE_PACKAGE_MARKERS):
        return None
    return "a zip archive"


def payload_kind(path: Path) -> str | None:
    """Why this file is a model / data payload rather than code, or None if it is code.

    The answer is a short phrase for a warning ("a pickle file", "an unrecognised
    binary file"). Never raises: a file that cannot be read is left to the archive,
    which will report the read error itself.
    """
    if path.suffix.lower() in WEIGHT_SUFFIXES:
        return "a model file"
    try:
        size = path.stat().st_size
        if size < CONTAINER_MIN_BYTES:
            return None
        with path.open("rb") as fh:
            head = fh.read(_HEAD_BYTES)
    except OSError:
        return None
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
        return "a pickle file"
    if head.startswith(b"PK\x03\x04"):
        return _zip_verdict(path)
    if len(head) >= 9 and head[8:9] == b"{":
        n = int.from_bytes(head[:8], "little")
        if 2 <= n < size:
            return "a safetensors model"
    for off, magic, what in _CONTAINERS:
        if head[off:off + len(magic)] == magic:
            return what
    if size < UNKNOWN_BINARY_MIN_BYTES:
        return None
    for off, magic in _CODE_OR_MEDIA:
        if head[off:off + len(magic)] == magic:
            return None
    if _is_text(head):
        return None
    return "an unrecognised binary file"
