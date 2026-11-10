"""``python -m uploadshield``: the same as the ``uploadshield`` command.

``python -m`` puts the current directory first on the import path; the console script
does not. Remove it, so scanning a folder of uploads cannot import code planted there
(a ``PIL/`` package, say). Commands that import project code add it back, after
installed packages.
"""

import sys
from pathlib import Path

if sys.path and sys.path[0] in ("", str(Path.cwd())):
    del sys.path[0]

from uploadshield.cli import main

raise SystemExit(main())
