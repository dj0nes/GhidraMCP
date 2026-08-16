#!/bin/sh
# Populate lib/ with the Ghidra jars this plugin compiles against, taken from a
# real install so the compile-time API matches the runtime API.
#
#   ./scripts/setup-libs.sh [/path/to/ghidra_X.Y.Z_PUBLIC]
#
# Run once per machine, and again after upgrading Ghidra.

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"
. "$here/ghidra-env.sh" "${1:-}"

MODULES="Base Decompiler Docking Generic Gui Project SoftwareModeling Utility"

echo "Ghidra $GHIDRA_VERSION ($GHIDRA_RELEASE) at $GHIDRA_INSTALL_DIR"
mkdir -p "$root/lib"

for module in $MODULES; do
    src="$(find "$GHIDRA_INSTALL_DIR/Ghidra" -name "$module.jar" -type f 2>/dev/null | head -1)"
    if [ -z "$src" ]; then
        echo "error: $module.jar not found under $GHIDRA_INSTALL_DIR/Ghidra" >&2
        echo "       (module layout may have changed in this Ghidra version)" >&2
        exit 1
    fi
    cp "$src" "$root/lib/$module.jar"
    echo "  $module.jar <- ${src#$GHIDRA_INSTALL_DIR/}"
done

# Gson ships with a version in its filename; the pom expects lib/gson.jar.
gson="$(find "$GHIDRA_INSTALL_DIR/Ghidra" -name 'gson-*.jar' -type f 2>/dev/null | head -1)"
[ -n "$gson" ] || ghidra_die "no gson-*.jar found under $GHIDRA_INSTALL_DIR/Ghidra"
cp "$gson" "$root/lib/gson.jar"
echo "  gson.jar <- ${gson#$GHIDRA_INSTALL_DIR/}"

echo
echo "lib/ now matches Ghidra $GHIDRA_VERSION. Next: ./scripts/build.sh"
