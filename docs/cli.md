# Command line

The `uploadshield` command inspects files the way an upload endpoint would. Use it to
find files that would be dangerous to accept (`scan`), to see exactly why a policy
accepts or refuses a file while you tune it (`validate`), and to look up policies and
violation codes (`policies`, `explain`). It uses only the standard library and ships
with the core package.

**On this page**

- [Running it](#running-it)
- [scan: is anything here dangerous?](#scan-is-anything-here-dangerous)
- [Verdicts](#verdicts)
- [validate: what would this policy do?](#validate-what-would-this-policy-do)
- [Choosing the policy](#choosing-the-policy)
- [policies and explain](#policies-and-explain)
- [Which files are read](#which-files-are-read)
- [Output](#output)
- [JSON output](#json-output)
- [Exit status](#exit-status)
- [Options reference](#options-reference)
- [Recipes](#recipes)

## Running it

```console
$ uvx uploadshield scan ~/Downloads                 # without installing anything
$ uv run uploadshield validate cv.pdf --policy pdf  # inside a project that depends on it
$ python -m uploadshield --version                  # the same, as a module
```

Optional scanners need their extra; with `uvx`, name it:
`uvx --from "uploadshield[magika]" uploadshield scan . --magika`. In a project, add it:
`uv add "uploadshield[magika]"`.

## scan: is anything here dangerous?

```console
$ uvx uploadshield scan uploads/
uploads/
  ✗ avatar.png  PHP script · 30 bytes
      type_not_allowed  PHP script files are not allowed.
      embedded_code  The file contains embedded code.  <?php
  ? backup.7z  7-Zip archive · 187 bytes
      type_not_allowed  Its contents cannot be inspected: unpack it and scan the files, or add --clamav.
  ! holiday.png  JPEG image · 14.6 KB
      extension_mismatch  The file extension '.png' does not match its content (JPEG image).
  ✗ invoice.pdf  PDF document · 293 bytes
      pdf_active_content  The PDF contains active content such as scripts or embedded files.  JS, JavaScript
  ✓ notes.txt  Plain text · 14 bytes
  ✓ report.pdf  PDF document · 180 KB

6 files in 0.0 s: 2 clean, 2 dangerous, 1 refused, 1 not verified.
What a code means: uploadshield explain <code>
```

`scan` answers one question: would this file be dangerous to accept as an upload? It
judges each file by its content with a built-in **scan policy**:

- **every format uploadshield can inspect is accepted** and checked with all content
  checks: archives, Office documents, XML, PDF, SVG, embedded code, images;
- **executables and HTML** are refused outright (dangerous whatever they contain);
- **archives it cannot open** (7-Zip, RAR) are reported as not verified: their
  contents were not inspected. ZIP and tar archives, plain or compressed, are opened;
- **names count when they are dangerous** (`shell.php.png`, `.htaccess`, `CON.txt`, path
  tricks): hidden files, names without an extension and empty files are fine; a name
  whose extension contradicts the content, or that is too long, is "refused";
- there is **no size limit**; a file too large for a check is reported as not
  verified, never skipped;
- nothing is sanitized.

Checks whose optional dependency is missing do nothing, and the command says so on
standard error: plain `uvx uploadshield` has no Pillow, so images are not decoded. Use
`uvx --from "uploadshield[images]" uploadshield scan ...` for image checks.

Each line shows what decided the file's verdict; `--json` lists every finding. Add a
second opinion with `--clamav ADDRESS`, `--yara RULES` (repeatable) or `--magika`.
They are checked before the first file is read: an unreachable `clamd`, rules that do
not compile or a missing extra stop the command with exit status 2.

`scan` judges files for *upload* safety: in a source tree every `.py` file is
"dangerous", because a `.py` upload would be a script. Point it at upload directories,
downloads, attachments and fixtures.

## Verdicts

| Verdict | Symbol | Meaning |
|---|---|---|
| clean | `✓` | nothing found |
| dangerous | `✗` | disguised scripts and executables, active PDF/Office/SVG content, archive bombs, hidden code, polyglots, malware, unsafe names |
| refused | `!` | harmless, but not acceptable as an upload (a JPEG named `.png`, a corrupt image) |
| not verified | `?` | it could not judge the file: an unknown format, 7-Zip and RAR archives, encrypted files, files too large for a check, unreadable files, an unavailable scanner |

A file takes the worst verdict of its violations (dangerous before not verified before
refused). Which code leads to which verdict is listed under
[Violation codes](https://github.com/IV1T3/uploadshield/blob/main/docs/refusals.md#violation-codes); `uploadshield explain` shows it too.
When the output cannot show `✓` and `✗` (for example a cp1252 console) it prints `OK`
and `X`.

## validate: what would this policy do?

```console
$ uploadshield validate uploads/gps.jpg --policy sanitized_images --save out
✓ uploads/gps.jpg  accepted by "sanitized_images"
  detected   JPEG image (image/jpeg), 791 bytes
  checks     ✓ size  ✓ filename  ✓ type  ✓ extension  ✓ embedded  ✓ image
             not applicable: archive, office, xml, pdf, svg
  sanitized  reencode_image, randomize_filename → e0e0f5b8b5984ed99f5b53068bedd63f.jpg (image/jpeg, 678 bytes, rewritten)
  saved      out/e0e0f5b8b5984ed99f5b53068bedd63f.jpg
```

```console
$ uploadshield validate uploads/avatar.png --policy images
✗ uploads/avatar.png  refused by "images" (dangerous)
  detected   PHP script (application/x-httpd-php), 30 bytes
  checks     ✓ size  ✓ filename  ✗ type
             not run after the first failure: extension, archive, office, xml, pdf, svg, embedded, image
               (--all-checks runs every check)
  ✗ type_not_allowed  PHP script files are not allowed.
      detected_type: application/x-httpd-php
  explain    uploadshield explain type_not_allowed
```

`validate` runs files through a policy unchanged, exactly as an endpoint would, and
shows:

- what was **detected**, and the **declared** type if you simulate one;
- every **check**: passed (`✓`), failed (`✗`), not applicable to this format, not run
  after the first failure (`fail_fast`), or **inactive** because an extra is missing
  (`image (needs uploadshield[images])`);
- every **violation** with all its details;
- what the **sanitizers** changed, and where the result was saved.

Simulate the client and the storage:

| Option | Effect |
|---|---|
| `--name NAME` | Judge the file under this name instead of its own (for one file or standard input). Shown as `as NAME`. |
| `--declared-type MIME` | The `Content-Type` a client would send. A warning tells you when the policy ignores it (`match_declared_type=False`). |
| `--all-checks` | Run every check instead of stopping at the first failure. |
| `--save DIR` | Write each accepted file as it would be stored (sanitized, under its new name) into `DIR`, which is created if needed. Existing files are never overwritten (exit status 2). Refused files are not saved. |
| `-` as `PATH` | Read the file from standard input; needs `--name`. |

```console
$ curl -s https://example.com/report | uploadshield validate - --name report.pdf --policy pdf
```

## Choosing the policy

`validate` and `policies` find policies in three places:

| `--policy` value | Example | Where it comes from |
|---|---|---|
| a built-in name | `--policy images` | `default`, `images`, `sanitized_images`, `pdf`, `documents`, `media`; see [Policies](https://github.com/IV1T3/uploadshield/blob/main/docs/policies.md#built-in-policies) |
| a dotted path | `--policy myproject.uploads.AVATARS` | a module-level `Policy` in your code |
| a name from Django settings | `--django --policy invoices` | your project's `UPLOADSHIELD["POLICIES"]` |

Without `--policy`, `validate` uses `default`, or with `--django` the project's
`DEFAULT_POLICY` (the built-in `default` if that is `None`).

- **`--django`** sets up Django with `DJANGO_SETTINGS_MODULE` and resolves names exactly
  as your project does. **`--settings MODULE`** names the settings module and implies
  `--django`.
- Dotted paths and `--django` import your project's code. Run the command from your
  project directory (`uv run uploadshield ...`): the current directory is then added to
  the import path, **after** installed packages, so nothing in it can shadow an
  installed library. `--pythonpath DIR` (repeatable) adds other directories first.
- `scan` never imports anything from the current directory, so scanning a folder of
  untrusted uploads cannot run code planted in it. This holds for both
  `uploadshield` and `python -m uploadshield`, which removes the current directory from
  the import path that `python -m` adds.

## policies and explain

```console
$ uploadshield policies
Policies (built in; --django adds your project's):
  default           22 formats (application, audio, image, text, video) · up to 50 MB
  documents         9 formats (application, text) · up to 25 MB
  images            4 formats (image) · up to 10 MB
  media             9 formats (audio, video) · up to 500 MB
  pdf               PDF document (application/pdf) · up to 25 MB
  sanitized_images  4 formats (image) · up to 10 MB · sanitizes: reencode_image, randomize_filename

Details: uploadshield policies <name>
```

`uploadshield policies NAME` shows what a policy allows, its size limit, the checks
in the order they run (with their non-default options), its sanitizers, and warns when
a check or sanitizer does nothing because an extra is missing. With `--django`, your
project's policies are listed too, marked `(project)`.

```console
$ uploadshield explain office_macros
office_macros  macros (dangerous)
  what      The document contains macros, ActiveX controls or DDE fields that run commands.
  why       The classic malicious-attachment payload.
  to allow  remove OfficeMacros() from content_checks (not recommended)
```

`uploadshield explain` without a code lists every code by verdict; several codes can
be given at once. An unknown code exits with status 2 and suggests the closest one.

## Which files are read

- **Directories** are walked recursively and listed under a heading with paths
  relative to them: in sorted order, each directory's files before its subdirectories.
- **`--exclude GLOB`** (repeatable) skips names or relative paths matching the glob
  inside directories, and does not descend into excluded directories:
  `--exclude .git --exclude '*.log'`. Paths you name on the command line are always
  read.
- **Symbolic links** you name on the command line are followed. Links found inside
  directories are skipped (listed as `skipped: symbolic link`) unless
  `--follow-symlinks`; directory cycles are detected and skipped.
- **Only regular files are read.** FIFOs and devices are skipped
  (`skipped: not a regular file`): reading them would block or never end. Sockets
  cannot be opened and are reported as not verified.
- **Skipped entries** are counted in the summary but never change the exit status.
- **Unreadable files** (permissions, files that vanish) are reported as not verified.
- **Paths that do not exist** stop the command with exit status 2 before anything is
  read.

## Output

- **Colour** is used on terminals. The order of precedence: `--color always|never`,
  then `NO_COLOR` (any non-empty value turns it off), then `FORCE_COLOR` (any value but
  `0` turns it on), then whether the output
  is a terminal (and `TERM` is not `dumb`). On Windows colour needs Windows Terminal or
  `FORCE_COLOR`.
- **Names are shown safely.** File names are attacker-controlled: control characters,
  line breaks, bidi overrides and undecodable bytes are printed as escapes
  (`a\x1b[2Jb.png`, `invoice\u202efdp.exe`), so a name cannot rewrite your terminal or
  forge lines.
- **`-q`/`--quiet`** shows only files that are not clean (the summary still counts all).
- **`-v`/`--verbose`** shows the engine's log messages on standard error, including
  tracebacks of checks that crashed. Without it they are kept out of the report.
- Warnings and errors go to standard error and the report to standard output; with
  `--json`, warnings are part of the document.
- **Ctrl-C** stops the command; the files inspected so far are summarized and the exit
  status is 130.

## JSON output

`--json` prints one document instead of the report. For `scan` and `validate`:

```json
{
  "schema": 1,
  "version": "2.1.1",
  "command": "scan",
  "policy": "scan",
  "files": [
    {
      "path": "uploads/invoice.pdf",
      "verdict": "dangerous",
      "sha256": "3daa55fa604b0548c2b9841441f097b1e8ed7c42b570b918f962d75a3375e90d",
      "name": "invoice.pdf",
      "ok": false,
      "errors": [
        {
          "code": "pdf_active_content",
          "message": "The PDF contains active content such as scripts or embedded files.",
          "check": "pdf",
          "details": {"reason": "active_content", "keywords": ["JS", "JavaScript"]},
          "verdict": "dangerous"
        }
      ],
      "size": 293,
      "detected_type": "application/pdf",
      "declared_type": null,
      "checks_run": ["size", "filename", "type", "extension", "pdf"],
      "sanitized": []
    }
  ],
  "summary": {
    "files": 1, "clean": 0, "refused": 0, "not_verified": 0, "dangerous": 1,
    "skipped": 0, "seconds": 0.02
  },
  "warnings": [],
  "interrupted": false,
  "exit_code": 1
}
```

| Field | Description |
|---|---|
| `schema` | `1`. Raised only when a field changes meaning or disappears; new fields may be added. |
| `version` | the uploadshield version |
| `command`, `policy` | `scan` or `validate`; the policy's name (`scan` for `scan`) |
| `files[]` | one entry per path, in the order inspected |
| `files[].path` | the path as given or found; `<stdin>` for standard input |
| `files[].verdict` | `clean`, `dangerous`, `refused`, `not_verified`; `null` for skipped entries |
| `files[].skipped` | why an entry was not read: `symbolic link`, `directory cycle`, `not a regular file` |
| `files[].error` | why a file could not be read (its verdict is `not_verified`) |
| `files[].sha256`, `name`, `ok`, `size`, `detected_type`, `declared_type`, `checks_run`, `sanitized` | the [result](https://github.com/IV1T3/uploadshield/blob/main/docs/python-api.md#results) of the file. `ok` is the policy's result, not the verdict: an empty file in a scan has `ok: false` and the verdict `clean` |
| `files[].errors[]` | every violation: `code`, `message`, `check`, `details`, `verdict` |
| `files[].sanitized_as` | when sanitized: `name`, `content_type`, `size`, `content_changed` |
| `files[].saved`, `files[].save_error` | with `--save`: where it was written, or why not |
| `summary` | counts per verdict, `skipped`, and `seconds` |
| `warnings` | e.g. the `--declared-type` warning |
| `interrupted` | `true` after Ctrl-C |
| `exit_code` | the command's exit status |

Sets in details become sorted lists and bytes become hex strings; the document is
ASCII-only (other characters are `\u` escapes).

`policies --json` prints `{"policies": [{name, allowed_types, max_size, allow_empty,
match_extension, match_declared_type, pipeline, sanitizers, fail_fast, inactive}]}`, and
`explain --json` prints `{"codes": [{code, verdict, condition, title, meaning, cause,
relax}]}`. These two have no `schema` field.

## Exit status

| Status | Meaning |
|---|---|
| `0` | every file is clean (`scan`) or accepted (`validate`); also `--help`, `--version`, `policies`, `explain` |
| `1` | at least one file is not clean or not accepted, including files that could not be read; also when the output pipe closes early (`\| head`) |
| `2` | the command could not run as asked: a usage error, a path that does not exist, `-` without `--name` or given twice, `--name` with several files or a directory, an unknown policy, a Django setup error, `clamd` not answering, YARA rules that do not compile, a missing extra, a `--save` directory that cannot be created or a file that could not be saved, an unknown code for `explain` |
| `130` | interrupted with Ctrl-C |

## Options reference

`uploadshield [--version] COMMAND ...`

**`scan PATH... [options]`** and **`validate PATH... [options]`**

| Option | Default | Description |
|---|---|---|
| `PATH` | | Files or directories; `-` reads standard input. |
| `--name NAME` | the file's own name | Judge the file under this name (required for standard input; one file only). |
| `--exclude GLOB` | none | Skip names or relative paths matching `GLOB`; repeatable. |
| `--follow-symlinks` | off | Follow symbolic links found inside directories. |
| `--clamav ADDRESS` | none | Also scan with `clamd`: `unix:///var/run/clamav/clamd.ctl` or `tcp://host:3310`. |
| `--yara RULES` | none | Also match YARA rules from a file or directory; repeatable. Needs `uploadshield[yara]`. |
| `--magika` | off | Also ask Google's Magika model. Needs `uploadshield[magika]`. |

**`validate` only**

| Option | Default | Description |
|---|---|---|
| `-p`, `--policy POLICY` | `default` (with `--django`: the project's `DEFAULT_POLICY`) | A policy name or a dotted path. |
| `--declared-type MIME` | none | The `Content-Type` a client would send. |
| `--all-checks` | off | Run every check instead of stopping at the first failure. |
| `--save DIR` | none | Write each accepted file as it would be stored; never overwrites. |

**`policies [NAME]`**: list the policies, or show one in detail.

**`explain [CODE...]`**: explain violation codes; all of them without arguments.

**Policy sources** (`validate`, `policies`)

| Option | Default | Description |
|---|---|---|
| `--django` | off | Use the Django project's `UPLOADSHIELD` settings (`DJANGO_SETTINGS_MODULE`). |
| `--settings MODULE` | none | The Django settings module; implies `--django`. |
| `--pythonpath DIR` | none | Also import policies from `DIR`; repeatable. |

**Output** (every command)

| Option | Default | Description |
|---|---|---|
| `--json` | off | Print one JSON document. |
| `--color {auto,always,never}` | `auto` | Colour the output. |
| `-q`, `--quiet` | off | Only show files that are not clean. |
| `-v`, `--verbose` | off | Show the engine's log messages. |

## Recipes

**Fail a CI job when fixtures contain something dangerous:**

```console
$ uvx uploadshield scan tests/fixtures --quiet
```

The exit status is 1 when anything is not clean. To fail only on dangerous files, use
the JSON document:

```console
$ uvx uploadshield scan uploads/ --json | jq -e '.summary.dangerous == 0'
```

**Audit an upload directory on a server**, with ClamAV, listing only findings:

```console
$ uvx uploadshield scan /srv/app/media --clamav unix:///var/run/clamav/clamd.ctl --quiet
```

**Check a policy change against sample files** before deploying it:

```console
$ uv run uploadshield validate samples/ --django --policy documents --quiet
```

**See every problem of one file at once:**

```console
$ uploadshield validate suspicious.docx --policy documents --all-checks
```
