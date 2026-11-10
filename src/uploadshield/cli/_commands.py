"""The four commands: ``scan``, ``validate``, ``policies`` and ``explain``."""

from __future__ import annotations

import difflib
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, TextIO

from uploadshield import presets, web
from uploadshield.core.types import format_size, get_type
from uploadshield.core.upload import Upload
from uploadshield.core.violations import cwe_for
from uploadshield.engine import validate

from ._json import dumps
from ._render import HumanReporter, JsonReporter, Reporter, missing_dependency
from ._scan import SetupError, scan_policy, scanner_checks
from ._style import Style, safe
from ._verdicts import CODE_INFO, CONDITIONS, Outcome, Summary, Verdict, judge
from ._walk import STDIN, Target, iter_targets, missing_paths, open_target

if TYPE_CHECKING:
    import argparse

    from uploadshield.core.violations import Code
    from uploadshield.policy import Policy

__all__ = ["COMMANDS", "Console"]


@dataclass(frozen=True, slots=True)
class Console:
    out: TextIO
    err: TextIO
    style: Style


# --------------------------------------------------------------------------- #
# scan and validate
# --------------------------------------------------------------------------- #


def scan(args: argparse.Namespace, console: Console) -> int:
    _check_paths(args)
    extra = scanner_checks(clamav=args.clamav, yara=args.yara, magika=args.magika)
    policy = scan_policy(extra)
    return _inspect_all(args, console, policy, scan=True)


def validate_command(args: argparse.Namespace, console: Console) -> int:
    _check_paths(args)
    policy, _ = _policies(args)
    extra = scanner_checks(clamav=args.clamav, yara=args.yara, magika=args.magika)
    if extra:
        policy = policy.extend(checks=extra)
    if args.all_checks:
        policy = policy.replace(fail_fast=False)
    if args.save is not None:
        try:
            args.save.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SetupError(f"cannot create {args.save}: {exc.strerror or exc}") from exc
    return _inspect_all(args, console, policy, scan=False)


def _check_paths(args: argparse.Namespace) -> None:
    if missing := missing_paths(args.paths):
        raise SetupError(f"no such file or directory: {', '.join(safe(p) for p in missing)}")
    if args.paths.count(STDIN) > 1:
        raise SetupError("standard input (-) can only be read once")
    if STDIN in args.paths and args.name is None:
        raise SetupError("reading standard input needs --name: the name a client would send")
    if args.name is not None and (len(args.paths) > 1 or Path(args.paths[0]).is_dir()):
        raise SetupError("--name applies to a single file or to standard input")


def _inspect_all(args: argparse.Namespace, console: Console, policy: Policy, *, scan: bool) -> int:
    reporter: Reporter
    if args.json:
        reporter = JsonReporter(console.out, command=args.command, policy=policy.name or None)
    else:
        reporter = HumanReporter(
            console.out,
            console.err,
            console.style,
            policy=policy,
            detailed=not scan,
            quiet=args.quiet,
        )
    for component in (*policy.pipeline, *policy.sanitizers):
        if (extra := missing_dependency(component)) is not None:
            reporter.warn(
                f"{component.name} does nothing without the {extra} extra: "
                f'uvx --from "uploadshield[{extra}]" uploadshield ..., '
                f"or uv add 'uploadshield[{extra}]' in your project"
            )
    declared = getattr(args, "declared_type", None)
    if declared and not policy.match_declared_type:
        reporter.warn(
            f'--declared-type has no effect: policy "{policy.name}" ignores the type a '
            "client declares (match_declared_type=False)"
        )
    summary = Summary()
    started = time.perf_counter()
    interrupted = False
    try:
        targets = iter_targets(
            args.paths, exclude=args.exclude, follow_symlinks=args.follow_symlinks
        )
        for target in targets:
            outcome = _inspect(
                target,
                policy,
                scan=scan,
                name=args.name,
                declared_type=declared,
                save=getattr(args, "save", None),
            )
            summary.add(outcome)
            reporter.file(outcome)
    except KeyboardInterrupt:
        interrupted = True
    summary.seconds = time.perf_counter() - started
    exit_code = 130 if interrupted else summary.exit_code
    reporter.finish(summary, interrupted=interrupted, exit_code=exit_code)
    return exit_code


def _inspect(
    target: Target,
    policy: Policy,
    *,
    scan: bool,
    name: str | None,
    declared_type: str | None,
    save: Path | None,
) -> Outcome:
    if target.skipped is not None:
        return _outcome(target, skipped=target.skipped)
    if target.error is not None:
        return _outcome(target, verdict=Verdict.NOT_VERIFIED, error=target.error)
    try:
        opened = open_target(target)
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        return _outcome(target, verdict=Verdict.NOT_VERIFIED, error=reason)
    if isinstance(opened, str):
        return _outcome(target, skipped=opened)
    stream, size = opened
    with stream:
        upload = Upload(
            stream=stream,
            name=target.name if name is None else name,
            size=size,
            declared_type=declared_type,
        )
        result = validate(upload, policy, sanitize=not scan)
        verdict, each = judge(result, scan=scan)
        outcome = _outcome(
            target, result=result, verdict=verdict, verdicts=each, sha256=web.sha256_of(stream)
        )
        if save is not None and result.ok:
            _save(outcome, stream, save)
    return outcome


def _outcome(target: Target, **fields: Any) -> Outcome:
    return Outcome(target.display, root=target.root, label=target.label or target.display, **fields)


def _save(outcome: Outcome, stream: IO[bytes], directory: Path) -> None:
    """Write what the application would store: the sanitized file, or the original."""
    result = outcome.result
    if result is None:  # pragma: no cover - only called for inspected files
        return
    sanitized = result.sanitized
    name = Path(sanitized.name if sanitized is not None else result.name).name
    if name in ("", ".", ".."):
        outcome.save_error = "the file has no usable name"
        return
    destination = directory / name
    try:
        with destination.open("xb") as fh:
            if sanitized is not None and sanitized.data is not None:
                fh.write(sanitized.data)
            else:
                stream.seek(0)
                shutil.copyfileobj(stream, fh)
    except FileExistsError:
        outcome.save_error = f"{destination} exists (files are never overwritten)"
        return
    except OSError as exc:
        outcome.save_error = f"{destination}: {exc.strerror or exc}"
        return
    outcome.saved = str(destination)


# --------------------------------------------------------------------------- #
# Policies
# --------------------------------------------------------------------------- #


def _policies(args: argparse.Namespace) -> tuple[Policy, dict[str, Policy]]:
    """The policy ``--policy`` names, and every policy known by name."""
    ref = getattr(args, "policy", None)
    if args.pythonpath:
        sys.path[:0] = [str(Path(p).resolve()) for p in args.pythonpath]
    if args.django or args.settings or "." in (ref or ""):
        # Project code is asked for: find it from the project directory, as manage.py
        # does - but last, so nothing in the current directory shadows an installed
        # package (a planted PIL/ in a folder of uploads, say).
        sys.path.append(str(Path.cwd()))
    if args.django or args.settings:
        try:
            from uploadshield.django.cli import configure

            config = configure(args.settings)
            known = dict(config.policies)
            if ref is None:
                return config.default_policy or presets.DEFAULT, known
            return config.resolve(ref), known
        except Exception as exc:
            raise SetupError(f"Django: {exc}") from exc
    known = dict(presets.BUILTIN_POLICIES)
    try:
        return web.resolve_policy(ref or "default", known), known
    except web.PolicyLookupError as exc:
        hint = "" if "." in (ref or "") else " (use --django for policies in Django settings)"
        raise SetupError(f"{exc}{hint}") from exc


def policies(args: argparse.Namespace, console: Console) -> int:
    args.policy = args.name
    chosen, known = _policies(args)
    s = console.style
    if args.json:
        selected = [chosen] if args.name else list(known.values())
        print(dumps({"policies": [_policy_data(p) for p in selected]}), file=console.out)
        return 0
    if args.name is None:
        source = (
            "your project's and the built-in ones"
            if args.django or args.settings
            else ("built in; --django adds your project's")
        )
        print(s.bold(f"Policies ({source}):"), file=console.out)
        width = max(len(n) for n in known)
        for name, policy in sorted(known.items()):
            own = s.dim(" (project)") if presets.BUILTIN_POLICIES.get(name) != policy else ""
            line = f"  {s.bold(name.ljust(width))}  {_policy_summary(policy, s)}{own}"
            print(line, file=console.out)
        print(s.dim("\nDetails: uploadshield policies <name>"), file=console.out)
        return 0
    _show_policy(chosen, console)
    return 0


def _policy_summary(policy: Policy, s: Style) -> str:
    size = f"up to {format_size(policy.max_size)}" if policy.max_size else "no size limit"
    parts = [_types_summary(policy), size]
    if policy.sanitizers:
        parts.append("sanitizes: " + ", ".join(x.name for x in policy.sanitizers))
    return f" {s.dot} ".join(parts)


def _types_summary(policy: Policy) -> str:
    types = sorted(policy.types)
    if len(types) <= 3:
        return ", ".join(_type_label(t) for t in types)
    families = sorted({t.split("/")[0] for t in types})
    return f"{len(types)} formats ({', '.join(families)})"


def _type_label(mime: str) -> str:
    found = get_type(mime)
    return f"{found.label} ({mime})" if found is not None else mime


def _show_policy(policy: Policy, console: Console) -> None:
    s = console.style

    def row(label: str, value: str) -> None:
        print(f"  {s.dim(f'{label:<12}')} {value}", file=console.out)

    print(s.bold(policy.name or "custom policy"), file=console.out)
    types = sorted(policy.types)
    row("allows", _type_label(types[0]) if types else "nothing")
    for mime in types[1:]:
        row("", _type_label(mime))
    limit = format_size(policy.max_size) if policy.max_size else "no limit"
    row("max size", f"{limit}; empty files {'allowed' if policy.allow_empty else 'refused'}")
    row("pipeline", f" {s.arrow} ".join(c.name for c in policy.pipeline))
    for component in (*policy.pipeline, *policy.sanitizers):
        _, _, options = component.deconstruct()
        if options:
            shown = ", ".join(f"{k}={_short(v)}" for k, v in options.items())
            row("", s.dim(f"{type(component).__name__}({shown})"))
    row("sanitizers", ", ".join(x.name for x in policy.sanitizers) or "none")
    row("names", "must match the content" if policy.match_extension else "not compared")
    row(
        "declared",
        "the client's Content-Type must match" if policy.match_declared_type else "ignored",
    )
    stops = "yes: stops at the first failing check" if policy.fail_fast else "no: runs all"
    row("fail fast", stops)
    for component in (*policy.pipeline, *policy.sanitizers):
        if (extra := missing_dependency(component)) is not None:
            row(
                "inactive",
                s.paint(
                    f"{component.name} does nothing without uploadshield[{extra}] "
                    f"(uv add 'uploadshield[{extra}]')",
                    "yellow",
                ),
            )


def _short(value: Any) -> str:
    text = repr(value)
    return text if len(text) <= 60 else text[:59] + "\u2026"


def _policy_data(policy: Policy) -> dict[str, Any]:
    return {
        "name": policy.name,
        "allowed_types": sorted(policy.types),
        "max_size": policy.max_size,
        "allow_empty": policy.allow_empty,
        "match_extension": policy.match_extension,
        "match_declared_type": policy.match_declared_type,
        "pipeline": [c.name for c in policy.pipeline],
        "sanitizers": [x.name for x in policy.sanitizers],
        "fail_fast": policy.fail_fast,
        "inactive": [
            c.name
            for c in (*policy.pipeline, *policy.sanitizers)
            if missing_dependency(c) is not None
        ],
    }


# --------------------------------------------------------------------------- #
# explain
# --------------------------------------------------------------------------- #


def explain(args: argparse.Namespace, console: Console) -> int:
    s = console.style
    known = {str(code): code for code in CODE_INFO}
    unknown = [c for c in args.codes if c not in known]
    if unknown:
        for code in unknown:
            close = difflib.get_close_matches(code, known, n=1)
            hint = f"; did you mean {close[0]}?" if close else ""
            print(f"uploadshield: unknown code {safe(code)!r}{hint}", file=console.err)
        print("Every code: uploadshield explain", file=console.err)
        return 2
    codes = [known[c] for c in args.codes]
    if args.json:
        selected = codes or list(CODE_INFO)
        data = [
            {"code": str(c), "verdict": CODE_INFO[c].verdict.value, "condition": CONDITIONS.get(c)}
            | {k: getattr(CODE_INFO[c], k) for k in ("title", "meaning", "cause", "relax")}
            | {"cwe": [{"id": ref.id, "name": ref.name} for ref in cwe_for(str(c))]}
            for c in selected
        ]
        print(dumps({"codes": data}), file=console.out)
        return 0
    if not codes:
        for verdict in (Verdict.DANGEROUS, Verdict.NOT_VERIFIED, Verdict.REFUSED):
            print(s.bold(verdict.label.capitalize()), file=console.out)
            for code, info in CODE_INFO.items():
                if info.verdict is verdict:
                    print(f"  {code!s:<30} {info.title}", file=console.out)
        print(s.dim("\nDetails: uploadshield explain <code>"), file=console.out)
        return 0
    for code in codes:
        _explain_one(code, console)
    return 0


def _explain_one(code: Code, console: Console) -> None:
    s = console.style
    info = CODE_INFO[code]
    verdict = info.verdict.label
    if condition := CONDITIONS.get(code):
        verdict += f"; {condition}"
    print(f"{s.bold(str(code))}  {info.title} {s.dim(f'({verdict})')}", file=console.out)
    for label, text in (("what", info.meaning), ("why", info.cause), ("to allow", info.relax)):
        print(f"  {s.dim(f'{label:<9}')} {text}", file=console.out)
    if refs := cwe_for(str(code)):
        cwes = ", ".join(f"{ref.id} {ref.name}" for ref in refs)
        print(f"  {s.dim('cwe'.ljust(9))} {cwes}", file=console.out)
    print("", file=console.out)


COMMANDS = {
    "scan": scan,
    "validate": validate_command,
    "policies": policies,
    "explain": explain,
}
