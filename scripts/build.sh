#!/bin/sh
# Build the plugin against a specific Ghidra install.
#
#   ./scripts/build.sh [/path/to/ghidra_X.Y.Z_PUBLIC] [extra mvn args...]
#
# The install's version is stamped into extension.properties, which is what
# Ghidra checks before it will load an extension at all.

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"

case "${1:-}" in
    -*|"") install_dir="" ;;
    *) install_dir="$1"; shift ;;
esac
. "$here/ghidra-env.sh" "$install_dir"

echo "Building GhidraMCP for Ghidra $GHIDRA_VERSION ($GHIDRA_INSTALL_DIR)"

missing=""
for jar in Base Decompiler Docking Generic Gui Project SoftwareModeling Utility gson; do
    [ -f "$root/lib/$jar.jar" ] || missing="$missing $jar.jar"
done
if [ -n "$missing" ]; then
    echo "error: lib/ is missing:$missing" >&2
    echo "       run ./scripts/setup-libs.sh first" >&2
    exit 1
fi

# Ghidra refuses to start under a JDK older than its minimum; javac targeting a
# newer release than the plugin runs on fails at class-load time, so warn early.
if [ -n "${GHIDRA_JAVA_MIN:-}" ]; then
    javac_ver="$(javac -version 2>&1 | sed -n 's/^javac \([0-9]*\).*/\1/p')"
    if [ -n "$javac_ver" ] && [ "$javac_ver" -lt "$GHIDRA_JAVA_MIN" ]; then
        echo "error: Ghidra $GHIDRA_VERSION needs JDK $GHIDRA_JAVA_MIN+, javac is $javac_ver" >&2
        exit 1
    fi
fi

cd "$root"
mvn -Dghidra.version="$GHIDRA_VERSION" \
    ${GHIDRA_JAVA_COMPILER:+-Dmaven.compiler.release="$GHIDRA_JAVA_COMPILER"} \
    clean package "$@"

echo
echo "  jar: target/GhidraMCP.jar"
echo "  zip: target/GhidraMCP-1.0-SNAPSHOT.zip  (ghidraVersion=$GHIDRA_VERSION)"
