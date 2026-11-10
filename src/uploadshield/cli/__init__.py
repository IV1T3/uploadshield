"""The ``uploadshield`` command: inspect files the way an upload endpoint would.

``uploadshield scan PATH...``      is anything here dangerous to accept as an upload?
``uploadshield validate PATH...``  would my policy accept this file, and why (not)?
``uploadshield policies [NAME]``   which policies exist, and what does one do?
``uploadshield explain [CODE]``    what does a violation code mean?

Exit status: 0 everything clean or accepted, 1 something was not, 2 the command could
not run as asked, 130 interrupted.  The command uses the standard library only.
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn, TextIO

if TYPE_CHECKING:
    from collections.abc import Generator, Sequence

__all__ = ["main"]

_DESCRIPTION = """\
Inspect files the way an upload endpoint would: by their content, not their name.

  scan      Is anything here dangerous to accept as an upload?
  validate  Would a policy accept these files - and why not?
  policies  The policies you can validate against.
  explain   What a violation code means and how to allow it.
"""
_EPILOG = """\
examples:
  uploadshield scan ~/Downloads
  uploadshield scan uploads/ --exclude '*.log' --quiet
  uploadshield validate avatar.jpg --policy sanitized_images --save out/
  curl -s https://example.com/f | uploadshield validate - --name f.pdf --policy pdf
  uploadshield validate cv.docx --django --policy documents
  uploadshield explain office_macros

exit status: 0 clean or accepted, 1 not, 2 usage or setup error, 130 interrupted
"""


class _UsageError(Exception):
    def __init__(self, parser: argparse.ArgumentParser, message: str) -> None:
        super().__init__(message)
        self.parser = parser


class _Exit(Exception):  # noqa: N818 - control flow for --help / --version
    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


class _Parser(argparse.ArgumentParser):
    """Raises instead of exiting, so :func:`main` always returns its status."""

    def error(self, message: str) -> NoReturn:
        raise _UsageError(self, message)

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        if message:
            sys.stderr.write(message)
        raise _Exit(status)


def build_parser() -> argparse.ArgumentParser:
    from uploadshield import __version__

    output = _Parser(add_help=False)
    group = output.add_argument_group("output")
    group.add_argument("--json", action="store_true", help="print one JSON document")
    group.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="colour the output (auto: on a terminal, unless NO_COLOR is set)",
    )
    group.add_argument(
        "-q", "--quiet", action="store_true", help="only show files that are not clean"
    )
    group.add_argument(
        "-v", "--verbose", action="store_true", help="show the engine's log messages"
    )

    files = _Parser(add_help=False)
    group = files.add_argument_group("files")
    group.add_argument("paths", nargs="+", metavar="PATH", help="files or directories; - for stdin")
    group.add_argument(
        "--name",
        metavar="NAME",
        help="judge the file under this name (required for stdin; simulates a client)",
    )
    group.add_argument(
        "--exclude",
        metavar="GLOB",
        action="append",
        default=[],
        help="skip names or paths matching GLOB (repeatable)",
    )
    group.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="follow symbolic links found in directories (those you name are always followed)",
    )

    scanners = _Parser(add_help=False)
    group = scanners.add_argument_group("extra scanners")
    group.add_argument(
        "--clamav",
        metavar="ADDRESS",
        help="also scan with clamd: unix:///var/run/clamav/clamd.ctl or tcp://host:3310",
    )
    group.add_argument(
        "--yara",
        metavar="RULES",
        action="append",
        help="also match YARA rules: a file or directory (repeatable; needs uploadshield[yara])",
    )
    group.add_argument(
        "--magika",
        action="store_true",
        help="also ask Google's Magika model (needs uploadshield[magika])",
    )

    project = _Parser(add_help=False)
    group = project.add_argument_group("where policies come from")
    group.add_argument(
        "--django",
        action="store_true",
        help="use the Django project's UPLOADSHIELD settings (DJANGO_SETTINGS_MODULE)",
    )
    group.add_argument(
        "--settings", metavar="MODULE", help="Django settings module (implies --django)"
    )
    group.add_argument(
        "--pythonpath",
        metavar="DIR",
        action="append",
        default=[],
        help="import policies from DIR too (for dotted paths; repeatable)",
    )

    parser = _Parser(
        prog="uploadshield",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"uploadshield {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    commands.add_parser(
        "scan",
        parents=[files, scanners, output],
        help="is anything here dangerous to accept as an upload?",
        description=(
            "Judge files by what they contain: executables and scripts in disguise, "
            "active PDF/Office/SVG content, archive bombs, hidden code, polyglots. Every "
            "format uploadshield can inspect is accepted; names only count when they are "
            "dangerous (shell.php.png, .htaccess)."
        ),
        epilog="verdicts: clean, dangerous, refused (harmless but unusual), not verified",
    )

    check = commands.add_parser(
        "validate",
        parents=[files, project, scanners, output],
        help="would a policy accept these files - and why not?",
        description=(
            "Run files through a policy exactly as an upload endpoint would, and show "
            "every check, every violation with its details, and what sanitizers changed."
        ),
    )
    group = check.add_argument_group("policy")
    group.add_argument(
        "-p",
        "--policy",
        metavar="POLICY",
        help="a policy name (uploadshield policies) or a dotted path (myapp.uploads.AVATARS); "
        "default: default, or the project's DEFAULT_POLICY with --django",
    )
    group.add_argument(
        "--declared-type", metavar="MIME", help="the Content-Type a client would send"
    )
    group.add_argument(
        "--all-checks",
        action="store_true",
        help="run every check instead of stopping at the first failure",
    )
    group.add_argument(
        "--save",
        metavar="DIR",
        type=Path,
        help="write each accepted file as it would be stored (sanitized); never overwrites",
    )

    listing = commands.add_parser(
        "policies",
        parents=[project, output],
        help="the policies you can validate against",
        description="List policies, or show what one allows and which checks it runs.",
    )
    listing.add_argument("name", nargs="?", metavar="NAME", help="show this policy in detail")

    explain = commands.add_parser(
        "explain",
        parents=[output],
        help="what a violation code means and how to allow it",
        description="Explain violation codes (all of them, without arguments).",
    )
    explain.add_argument("codes", nargs="*", metavar="CODE")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command; returns the exit status (also for ``--help`` and usage errors)."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except _Exit as exc:
        return exc.status
    except _UsageError as exc:
        exc.parser.print_usage(sys.stderr)
        print(f"{exc.parser.prog}: error: {exc}", file=sys.stderr)
        return 2

    from ._commands import COMMANDS, Console
    from ._scan import SetupError
    from ._style import Style, color_enabled

    out, err = sys.stdout, sys.stderr
    for stream in (out, err):
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(errors="backslashreplace")  # ty: ignore[unresolved-attribute]
    console = Console(out, err, Style(out, color=color_enabled(args.color, out)))
    with _engine_logs(verbose=args.verbose, stream=err):
        try:
            return COMMANDS[args.command](args, console)
        except SetupError as exc:
            print(f"uploadshield: {exc}", file=err)
            return 2
        except KeyboardInterrupt:
            return 130
        except BrokenPipeError:
            # The reader went away (| head): stop quietly, as other tools do.
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, out.fileno())
            return 1


@contextlib.contextmanager
def _engine_logs(*, verbose: bool, stream: TextIO) -> Generator[None, None, None]:
    """Keep engine logs (tracebacks of crashed checks) out of the report unless asked."""
    logger = logging.getLogger("uploadshield")
    handler: logging.Handler
    if verbose:
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    else:
        handler = logging.NullHandler()
    saved = logger.propagate, logger.level
    logger.addHandler(handler)
    logger.propagate = False
    if verbose:
        logger.setLevel(logging.DEBUG)
    try:
        yield
    finally:
        logger.removeHandler(handler)
        logger.propagate, logger.level = saved
