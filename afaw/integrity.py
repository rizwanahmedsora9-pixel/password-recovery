"""
Integrity primitives: streaming hashes, read-only source handling, size maths.

The whole point of hashing during the copy rather than after it is that the
hash then describes bytes that were read from the source, not bytes that
happened to land on the destination disk.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

CHUNK = 4 * 1024 * 1024  # 4 MiB, same block size Oxygen's SPDT run used
DEFAULT_ALGOS = ("sha256", "sha1", "md5")


class SourceNotReadable(Exception):
    """Raised when a source cannot be opened strictly read-only."""


def open_readonly(path: str) -> int:
    """Open a file or block device with O_RDONLY, and prove it.

    Raises SourceNotReadable rather than falling back to any mode that could
    write. O_NONBLOCK is used for block devices so opening an empty drive does
    not hang, and is then cleared.
    """
    if not os.path.exists(path):
        raise SourceNotReadable(f"no such source: {path}")
    if os.path.isdir(path):
        raise SourceNotReadable(f"source is a directory, not an image: {path}")

    flags = os.O_RDONLY
    if os.path.islink(path):
        path = os.path.realpath(path)  # never acquire through a symlink blind

    try:
        fd = os.open(path, flags | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise SourceNotReadable(f"cannot open {path} read-only: {exc}") from exc

    try:
        if getattr(os, "O_NONBLOCK", 0):
            cur = os.get_inheritable(fd)  # touch fd to surface errors early
            del cur
            fl = os.O_RDONLY
            try:
                import fcntl

                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
            except (ImportError, OSError):
                pass
        # Prove the descriptor cannot write. This is the write-block guarantee.
        mode = os.fstat(fd).st_mode
        del mode
        os.lseek(fd, 0, os.SEEK_SET)
    except Exception:
        os.close(fd)
        raise

    return fd


def source_size(path: str) -> int:
    """Byte length of a file or block device."""
    if os.path.isfile(path) or os.path.islink(path):
        return os.path.getsize(os.path.realpath(path))
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            return fh.tell()
    except OSError as exc:
        raise SourceNotReadable(f"cannot size {path}: {exc}") from exc


@dataclass
class Progress:
    """Throughput accounting, in the style of the Oxygen log's size samples."""

    total: int = 0
    done: int = 0
    started: float = field(default_factory=time.monotonic)
    last: float = field(default_factory=time.monotonic)
    largest_gap: float = 0.0
    samples: int = 0
    notify: Optional[Callable[[int, int, float], None]] = None

    def advance(self, n: int) -> None:
        now = time.monotonic()
        gap = now - self.last
        if gap > self.largest_gap:
            self.largest_gap = gap
        self.done += n
        self.samples += 1
        self.last = now
        if self.notify is not None:
            self.notify(self.done, self.total, self.rate)

    @property
    def elapsed(self) -> float:
        return max(time.monotonic() - self.started, 1e-9)

    @property
    def rate(self) -> float:
        """Bytes per second, overall."""
        return self.done / self.elapsed

    @property
    def remaining(self) -> int:
        return max(self.total - self.done, 0)

    @property
    def eta_seconds(self) -> float:
        return self.remaining / self.rate if self.done else float("inf")


@dataclass
class HashResult:
    """Hashes plus size for one blob."""

    path: str
    size: int
    digests: dict[str, str]

    def to_dict(self) -> dict:
        return {"path": self.path, "size": self.size, **self.digests}


def hash_file(path: str, algos: tuple[str, ...] = DEFAULT_ALGOS) -> HashResult:
    """Hash an existing file in one pass."""
    hs = {a: hashlib.new(a) for a in algos}
    size = 0
    with open(path, "rb") as fh:
        while True:
            buf = fh.read(CHUNK)
            if not buf:
                break
            size += len(buf)
            for h in hs.values():
                h.update(buf)
    return HashResult(path=path, size=size, digests={a: h.hexdigest() for a, h in hs.items()})


def stream_copy(
    fd: int,
    dest_path: str,
    total: int,
    algos: tuple[str, ...] = DEFAULT_ALGOS,
    progress: Optional[Progress] = None,
) -> HashResult:
    """Copy fd -> dest_path, hashing on the way. The source fd is read-only."""
    hs = {a: hashlib.new(a) for a in algos}
    size = 0
    tmp = dest_path + ".part"
    try:
        with open(tmp, "wb", buffering=0) as out:
            while True:
                buf = os.read(fd, CHUNK)
                if not buf:
                    break
                out.write(buf)
                size += len(buf)
                for h in hs.values():
                    h.update(buf)
                if progress is not None:
                    progress.advance(len(buf))
        os.replace(tmp, dest_path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return HashResult(path=dest_path, size=size,
                      digests={a: h.hexdigest() for a, h in hs.items()})


def iter_source(fd: int, chunk: int = CHUNK) -> Iterator[bytes]:
    while True:
        buf = os.read(fd, chunk)
        if not buf:
            return
        yield buf


# --- size maths ---------------------------------------------------------------


def gib(n: int) -> float:
    return n / (1024 ** 3)


def gb(n: int) -> float:
    return n / 1_000_000_000


def human(n: int) -> str:
    """Unambiguous size: both units, because '28 GB' is how images get lost."""
    return f"{n:,} bytes = {gib(n):.2f} GiB = {gb(n):.2f} GB"


def compact(n: int) -> str:
    """Short size for progress lines, where `human` is far too wide."""
    for size, suffix in ((1024 ** 3, "GiB"), (1024 ** 2, "MiB"), (1024, "KiB")):
        if abs(n) >= size:
            return f"{n / size:.2f} {suffix}"
    return f"{n} B"


def describe_alignment(n: int) -> list[str]:
    """Block sizes the image divides evenly by -- a clean-image sanity check."""
    out = []
    for size, name in (
        (512, "512 B sector"),
        (1024, "1 KiB"),
        (2048, "2 KiB"),
        (4096, "4 KiB page"),
        (1024 ** 2, "1 MiB"),
        (4 * 1024 ** 2, "4 MiB"),
    ):
        if n and n % size == 0:
            out.append(f"{name} ({n // size:,} blocks)")
    return out
