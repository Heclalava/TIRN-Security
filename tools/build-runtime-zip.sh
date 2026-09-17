#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

PKG="TIRN-Security-$(git describe --tags --always)-runtime-install.zip"

echo "=== BUILD RUNTIME HELPERS ==="

(
    cd tools/apklabel
    GO111MODULE=on GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o apklabel-arm64 .
)

(
    cd tools/appaudit
    GO111MODULE=on GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o appaudit-arm64 .
)

(
    cd tools/apphelper
    GO111MODULE=on GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o apphelper-arm64 .
)

echo "=== VERIFY TRACKED RUNTIME HELPERS ==="

for pair in \
    "apklabel tools/apklabel/apklabel-arm64" \
    "appaudit tools/appaudit/appaudit-arm64" \
    "apphelper tools/apphelper/apphelper-arm64"
do
    set -- $pair
    if ! cmp -s "$1" "$2"; then
        echo "ERROR: tracked runtime binary does not match current build: $1" >&2
        echo "Update and commit $1 before building a release package." >&2
        exit 1
    fi
    echo "$1: MATCH"
done

echo "=== BUILD ZIP ==="

rm -f "$PKG"

python3 - "$PKG" <<'PY'
import subprocess
import sys
import zipfile

out = sys.argv[1]
excluded = {".gitignore", "Screenshot.png"}

keep = []
for line in subprocess.check_output(["git", "ls-files", "-s"], text=True).splitlines():
    meta, path = line.split("\t", 1)
    mode, obj, stage = meta.split()
    if path in excluded or path.startswith("tools/"):
        continue
    keep.append((path, int(mode, 8)))

with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for path, mode in keep:
        data = subprocess.check_output(["git", "show", f"HEAD:{path}"])
        info = zipfile.ZipInfo(path)
        info.date_time = (1980, 1, 1, 0, 0, 0)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (mode << 16) | 0x80000000
        z.writestr(info, data)

print(f"Created {out}")
PY

echo "=== VERIFY PACKAGE ==="

python3 - "$PKG" <<'PY'
from pathlib import Path
import hashlib
import sys
import zipfile

pkg = Path(sys.argv[1])
z = zipfile.ZipFile(pkg)
names = z.namelist()

if len(names) != len(set(names)):
    duplicates = sorted({n for n in names if names.count(n) > 1})
    raise SystemExit("ERROR: duplicate ZIP entries: " + ", ".join(duplicates))

excluded = [
    n for n in names
    if n == ".gitignore" or n == "Screenshot.png" or n.startswith("tools/")
]
if excluded:
    raise SystemExit("ERROR: excluded files present: " + ", ".join(excluded))

pairs = {
    "apklabel": Path("tools/apklabel/apklabel-arm64"),
    "appaudit": Path("tools/appaudit/appaudit-arm64"),
    "apphelper": Path("tools/apphelper/apphelper-arm64"),
}

for name, source in pairs.items():
    packaged = z.read(name)
    built = source.read_bytes()
    if packaged != built:
        raise SystemExit(f"ERROR: packaged {name} does not match current build")
    print(f"{name}: MATCH {hashlib.sha256(packaged).hexdigest()}")

if z.testzip() is not None:
    raise SystemExit("ERROR: ZIP integrity check failed")

print(f"Files: {len(names)}")
print(f"Size: {pkg.stat().st_size} bytes")
print(f"SHA-256: {hashlib.sha256(pkg.read_bytes()).hexdigest()}")
print("Duplicate entries: NONE")
print("Excluded files: NONE")
print("ZIP integrity: OK")
PY

echo "=== COMPLETE ==="
echo "$PKG"
