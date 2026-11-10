"""The policies the evaluation runs against, by name.

Both the corpus generator and the per-environment runner import this, so a case
labelled against policy ``images`` is scored against the very same policy everywhere.
Pure stdlib + uploadshield, so it imports under a base install with no extras.
"""

from __future__ import annotations

from uploadshield import MB, Policy, presets

# The six shipped presets, plus policies that accept formats no preset does, so the
# archive and markup checks can be exercised against a policy that actually allows them.
POLICIES: dict[str, Policy] = {
    "default": presets.DEFAULT,
    "images": presets.IMAGES,
    "sanitized_images": presets.SANITIZED_IMAGES,
    "pdf": presets.PDF,
    "documents": presets.DOCUMENTS,
    "media": presets.MEDIA,
    # Archives: ZIP and tar (plain + compressed), with a real size cap.
    "archives": Policy(
        name="archives",
        allowed_types={
            "application/zip",
            "application/x-tar",
            "application/gzip",
            "application/x-bzip2",
            "application/x-xz",
        },
        max_size=50 * MB,
    ),
    # Everything inspectable via wildcards: the broadest sensible allow-list.
    "wildcard_all": Policy(
        name="wildcard_all",
        allowed_types={"image/*", "audio/*", "video/*", "application/*", "text/*"},
        max_size=100 * MB,
    ),
    # Markup that browsers run script in: only accepted when named explicitly.
    "markup": Policy(
        name="markup",
        allowed_types={"image/svg+xml", "application/xml", "text/html", "text/plain"},
        max_size=5 * MB,
    ),
    # Opts into declared Content-Type matching (off by default): used to test that the
    # DeclaredTypeMatches check refuses a client Content-Type that contradicts the bytes.
    "strict_declared": Policy(
        name="strict_declared",
        allowed_types={"image/*", "audio/*", "video/*", "application/*", "text/*"},
        max_size=100 * MB,
        match_declared_type=True,
    ),
}
