#!/bin/bash
# Run the evaluation across Python versions and extra combinations.
# Each environment is isolated: only the requested extras are installed, so "base"
# truly has no Pillow/Magika/YARA. The frozen corpus is scored identically by all.
#
# Usage: bash evaluation/run_all.sh path/to/uploadshield-<version>-py3-none-any.whl
set -u
EVAL="$(cd "$(dirname "$0")" && pwd)"
CORPUS="$EVAL/corpus"
RESULTS="$EVAL/results"
WHEEL="$1"
rm -f "$RESULTS"/*.jsonl

run() {  # label python "extra specs..."
  local label="$1" py="$2"; shift 2
  local withs=(--with "$WHEEL")
  for spec in "$@"; do withs+=(--with "$spec"); done
  echo "=== $label (python $py) ==="
  uv run --isolated --no-project --python "$py" "${withs[@]}" -- \
    python "$EVAL/run_eval.py" "$CORPUS" "$RESULTS" --label "$label" --repeats 3 \
    || echo "FAILED: $label"
}

# Base (no extras) on every supported interpreter: the structural core, comparable across versions.
for py in 3.11 3.12 3.13 3.14 3.15; do run "py$py-base" "$py"; done

# Extras on 3.13 (all available): isolate each one's effect, then all together.
run "py3.13-images" 3.13 pillow
run "py3.13-yara"   3.13 yara-python
run "py3.13-magika" 3.13 magika
run "py3.13-all"    3.13 pillow yara-python magika

# Extras where wheels exist: yara/magika thin out on the newest interpreters.
run "py3.11-all" 3.11 pillow yara-python magika
run "py3.12-all" 3.12 pillow yara-python magika
run "py3.14-images+magika" 3.14 pillow magika
run "py3.15-images" 3.15 pillow

echo "=== done ==="
ls -1 "$RESULTS"/*.jsonl | wc -l
