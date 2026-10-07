#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

PKG="TIRN-Security-$(git describe --tags --always)-armv7-runtime-install.zip"

echo "=== BUILD RUNTIME HELPERS ==="

(
    cd tools/apklabel
    GO111MODULE=on GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -buildvcs=false -o apklabel-armv7 .
)

(
    cd tools/appaudit
    GO111MODULE=on GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -buildvcs=false -o appaudit-armv7 .
)

(
    cd tools/apphelper
    GO111MODULE=off GOOS=linux GOARM=7 GOARCH=arm CGO_ENABLED=0 go build -buildvcs=false -o apphelper-armv7 .
)

echo "=== VERIFY ARMV7 RUNTIME HELPERS ==="

for pair in \
    "apklabel tools/apklabel/apklabel-armv7" \
    "appaudit tools/appaudit/appaudit-armv7" \
    "apphelper tools/apphelper/apphelper-armv7"
do
    set -- $pair
    test -f "$2" || { echo "ERROR: ARMv7 binary missing: $2" >&2; exit 1; }
    echo "$1: BUILT"
done

echo "=== BUILD ZIP ==="

rm -f "$PKG"

python3 - "$PKG" <<'PY'
import subprocess
import sys
import zipfile
from pathlib import Path

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
        armv7 = {
            "apklabel": Path("tools/apklabel/apklabel-armv7"),
            "appaudit": Path("tools/appaudit/appaudit-armv7"),
            "apphelper": Path("tools/apphelper/apphelper-armv7"),
        }
        working_tree = {
            "refresh_apps": Path("refresh_apps"),
            "service.sh": Path("service.sh"),
        }
        if path in armv7:
            data = armv7[path].read_bytes()
        elif path in working_tree:
            data = working_tree[path].read_bytes()
        else:
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
    "apklabel": Path("tools/apklabel/apklabel-armv7"),
    "appaudit": Path("tools/appaudit/appaudit-armv7"),
    "apphelper": Path("tools/apphelper/apphelper-armv7"),
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
