#!/usr/bin/env bash
# Real-HTTP smoke test for examples/{django,flask,fastapi}_app.py.
# Usage: examples/smoke.sh BASE_URL SAMPLES_DIR   (samples: upload-demo/scripts/make_samples.py)
set -uo pipefail
BASE=$1; S=$2; PASS=0; FAIL=0
TMP=$(mktemp -d "${TMPDIR:-/tmp}/smoke.XXXX"); trap 'rm -rf "$TMP"' EXIT
check() {
  if [[ "$3" == "$2" ]]; then PASS=$((PASS + 1)); printf "  ok    %-62s %s\n" "$1" "$3"
  else FAIL=$((FAIL + 1)); printf "  FAIL  %-62s expected %s got %s\n" "$1" "$2" "$3"; fi
}
contains() {
  if [[ "$3" == *"$2"* ]]; then PASS=$((PASS + 1)); printf "  ok    %-62s contains %s\n" "$1" "$2"
  else FAIL=$((FAIL + 1)); printf "  FAIL  %-62s missing %s in %.150s\n" "$1" "$2" "$3"; fi
}
status() { curl -s -o /dev/null -w "%{http_code}" -H "Accept: application/json" "$@"; }
body() { curl -s -H "Accept: application/json" "$@"; }
get() {  # get JSON PATH, e.g. get "$json" files.0.name ("*" joins a list); FastAPI's "detail" is unwrapped
  python3 - "$1" "$2" 2>/dev/null <<'PY'
import json, sys
data = json.loads(sys.argv[1])
if isinstance(data, dict) and isinstance(data.get("detail"), dict):
    data = data["detail"]
keys = sys.argv[2].split(".")
for i, key in enumerate(keys):
    if key == "*":
        rest = ".".join(keys[i + 1 :])
        data = " ".join(str(item[rest]) if rest else str(item) for item in data)
        break
    data = data[int(key)] if isinstance(data, list) else data[key]
print(data)
PY
}
curl -s --retry 30 --retry-connrefused --retry-delay 1 -o /dev/null "$BASE/" || true
echo "== $BASE"

echo "-- per-view policies"
json=$(body -F "file=@$S/ok.pdf;type=text/plain" "$BASE/documents")
contains "valid PDF accepted, type from bytes" '"application/pdf"' "$json"
check "...delivered byte-for-byte" "$(shasum -a 256 "$S/ok.pdf" | cut -d" " -f1)" "$(get "$json" files.0.sha256)"
check "PHP disguised as PNG -> 415" 415 "$(status -F "file=@$S/shell.php;filename=cat.png;type=image/png" "$BASE/documents")"
contains "...machine-readable code" "type_not_allowed" "$(body -F "file=@$S/shell.php;filename=cat.png" "$BASE/documents")"
check "PDF with JavaScript -> 400" 400 "$(status -F "file=@$S/js.pdf" "$BASE/documents")"
check "DOCX with VBA macros -> 400" 400 "$(status -F "file=@$S/macro.docx" "$BASE/documents")"
check "SVG with an onload handler -> 415" 415 "$(status -F "file=@$S/xss.svg" "$BASE/legacy")"
check "120 MiB executable named report.pdf -> refused" refused "$(c=$(status -F "file=@$S/huge.bin;filename=report.pdf" "$BASE/documents"); [[ $c == 413 || $c == 415 ]] && echo refused || echo "$c")"
{ printf '\xff\xd8\xff\xe0'; head -c $((11 * 1024 * 1024)) /dev/zero; } > "$TMP/big.jpg"
check "11 MiB avatar: the view's 10 MB limit, not the 50 MB default -> 413" 413 "$(status -F "file=@$TMP/big.jpg" "$BASE/avatar")"

echo "-- names (the safety net on a view without configuration)"
check "shell.php.png -> 400" 400 "$(status -F "file=@$S/ok.png;filename=shell.php.png" "$BASE/legacy")"
check "drive-relative C:x.png -> 400" 400 "$(status -F "file=@$S/ok.png;filename=C:x.png" "$BASE/legacy")"
c=$(status -F "file=@$S/ok.png;filename=../../x.png" "$BASE/legacy")
name=$(get "$(body -F "file=@$S/ok.png;filename=../../x.png" "$BASE/legacy")" files.0.name)
check "../../x.png refused, or stripped to x.png by the framework" yes "$([[ $c == 400 || $name == x.png ]] && echo yes || echo "$c $name")"
c=$(status -F "file=@$S/shell.php;filename=" "$BASE/legacy")
json=$(body -F "file=@$S/shell.php;filename=" "$BASE/legacy")
check "PHP in a part without a filename never reaches the view" yes "$([[ $c == 400 || ($c == 200 && -z $(get "$json" files.*.name)) ]] && echo yes || echo "$c $json")"
check "valid PNG on the safety-net view -> 200" 200 "$(status -F "file=@$S/ok.png" "$BASE/legacy")"
check "...with the detected content type" image/png "$(get "$(body -F "file=@$S/ok.png;type=text/html" "$BASE/legacy")" files.0.content_type)"

echo "-- sanitization and several files"
original=$(shasum -a 256 "$S/gps.jpg" | cut -d" " -f1)
json=$(body -F "file=@$S/gps.jpg;filename=me.jpg" "$BASE/avatar")
name=$(get "$json" files.0.name)
check "avatar stored under a random name (32 hex + .jpg)" 36 "${#name}"
check "avatar was re-encoded (bytes changed)" yes "$([[ $(get "$json" files.0.sha256) != "$original" ]] && echo yes || echo no)"
json=$(body -F "files=@$S/ok.png" -F "files=@$S/gps.jpg" "$BASE/gallery")
check "gallery: two images, in order" "ok.png gps.jpg" "$(get "$json" files.*.name)"
json=$(body -F "files=@$S/ok.png" -F "files=@$S/shell.php;filename=cat.png" "$BASE/gallery")
check "gallery: one bad file refuses the request, and only it is listed" cat.png "$(get "$json" files.*.name)"

if [[ $(status "$BASE/profile") == 200 ]]; then
  echo "-- Django: HTML form with inline errors (CSRF-protected)"
  curl -s -c "$TMP/jar" -o /dev/null "$BASE/profile"
  token=$(awk '/csrftoken/ {print $7}' "$TMP/jar")
  csrf=(-b "$TMP/jar" -F "csrfmiddlewaretoken=$token" -F "nickname=mallory")
  check "form without a CSRF token -> 403" 403 "$(status -F "nickname=x" -F "picture=@$S/ok.png" "$BASE/profile")"
  page=$(curl -s "${csrf[@]}" -F "picture=@$S/shell.php;filename=me.png" "$BASE/profile")
  contains "PHP as me.png -> inline form error" "PHP script files are not allowed." "$page"
  contains "...and the form keeps its other values" 'value="mallory"' "$page"
  json=$(curl -s "${csrf[@]}" -F "picture=@$S/gps.jpg;filename=me.jpg" "$BASE/profile")
  name=$(get "$json" files.0.name)
  check "valid picture -> re-encoded under a random name" 36 "${#name}"
fi

echo "== $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
