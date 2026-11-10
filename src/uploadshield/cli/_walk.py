"""Turn command-line paths into files to inspect, without surprises.

* Directories are walked in sorted order, so output is stable.
* Symbolic links named on the command line are followed; links found while walking
  are skipped unless asked for, and directory cycles are cut.
* Only regular files are read.  A FIFO would block forever and ``/dev/zero`` never
  ends, so files are opened non-blocking and checked with ``fstat`` first.
"""

from __future__ import annotations

import contextlib
import dataclasses
import fnmatch
import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

__all__ = ["STDIN", "Target", "iter_targets", "missing_paths", "open_target"]

STDIN = "-"
_CHUNK = 1 << 20


@dataclass(frozen=True, slots=True)
class Target:
    """One thing to inspect.  ``path`` is ``None`` for standard input.

    ``display`` is the full path as given; files found in a directory also have a
    ``root`` (that directory, as given) and a ``label`` relative to it.
    """

    display: str
    name: str
    path: Path | None = None
    follow: bool = True  # may the final component be a symbolic link?
    error: str | None = None
    skipped: str | None = None
    root: str | None = None
    label: str = ""


def missing_paths(paths: Iterable[str]) -> list[str]:
    return [p for p in paths if p != STDIN and not os.path.lexists(p)]


def iter_targets(
    paths: Iterable[str], *, exclude: Iterable[str] = (), follow_symlinks: bool = False
) -> Iterator[Target]:
    patterns = tuple(exclude)
    for arg in paths:
        if arg == STDIN:
            yield Target(display="<stdin>", name="", label="<stdin>")
            continue
        path = Path(arg)
        if path.is_dir():  # follows a link named on the command line, like find -H
            for target in _walk(path, patterns, follow_symlinks=follow_symlinks):
                label = Path(target.display).relative_to(path).as_posix()
                yield dataclasses.replace(target, root=arg, label=label)
        else:
            yield Target(display=arg, name=path.name, path=path, label=arg)


def _excluded(name: str, relative: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(relative, p) for p in patterns)


def _walk(root: Path, patterns: tuple[str, ...], *, follow_symlinks: bool) -> Iterator[Target]:
    seen: set[tuple[int, int]] = set()
    try:
        info = root.stat()
        seen.add((info.st_dev, info.st_ino))
    except OSError:
        pass
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as scan:
                entries = sorted(scan, key=lambda e: e.name)
        except OSError as exc:
            yield Target(str(directory), directory.name, directory, error=_reason(exc))
            continue
        subdirectories: list[Path] = []
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            if _excluded(entry.name, relative, patterns):
                continue
            link = entry.is_symlink()
            if link and not follow_symlinks:
                yield Target(str(path), entry.name, path, skipped="symbolic link")
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=follow_symlinks)
            except OSError as exc:
                yield Target(str(path), entry.name, path, error=_reason(exc))
                continue
            if is_dir:
                try:
                    info = entry.stat(follow_symlinks=True)
                except OSError as exc:
                    yield Target(str(path), entry.name, path, error=_reason(exc))
                    continue
                if (key := (info.st_dev, info.st_ino)) in seen:
                    yield Target(str(path), entry.name, path, skipped="directory cycle")
                    continue
                seen.add(key)
                subdirectories.append(path)
            else:
                yield Target(str(path), entry.name, path, follow=follow_symlinks)
        stack.extend(reversed(subdirectories))  # depth first, in sorted order


def open_target(target: Target) -> tuple[IO[bytes], int] | str:
    """An open binary stream and its size, or why the target is not a regular file.

    Raises :class:`OSError` when the file cannot be read (reported as not verified).
    """
    if target.path is None:
        return _spool_stdin()
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    if not target.follow:
        flags |= getattr(os, "O_NOFOLLOW", 0)  # it was not a link a moment ago
    fd = os.open(target.path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            return "not a regular file"
        return os.fdopen(fd, "rb"), info.st_size
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise


def _spool_stdin() -> tuple[IO[bytes], int]:
    # A copy of our own: the engine closes the streams it copies, and --save needs
    # the bytes afterwards.
    spool = tempfile.SpooledTemporaryFile(max_size=16 * _CHUNK)  # noqa: SIM115
    size = 0
    source = sys.stdin.buffer
    while chunk := source.read(_CHUNK):
        spool.write(chunk)
        size += len(chunk)
    spool.seek(0)
    return spool, size


def _reason(exc: OSError) -> str:
    return exc.strerror or type(exc).__name__
