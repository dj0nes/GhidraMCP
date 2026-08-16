#!/bin/sh
# Install the built plugin into the per-user Ghidra extensions directory.
#
#   ./scripts/install.sh [/path/to/ghidra_X.Y.Z_PUBLIC] [--copy]
#
# By default the jar and the bridge script are symlinked back to this repo, so
# `./scripts/build.sh` + a Ghidra restart is the whole edit loop. Use --copy for
# a standalone install (or on Windows, where symlinks need elevation).
#
# Restart Ghidra afterwards, then enable GhidraMCPPlugin under
# File -> Configure -> Developer.

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"

mode=link
install_dir=""
for arg in "$@"; do
    case "$arg" in
        --copy) mode=copy ;;
        --link) mode=link ;;
        -*) echo "unknown option: $arg" >&2; exit 1 ;;
        *) install_dir="$arg" ;;
    esac
done
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) mode=copy ;; esac

. "$here/ghidra-env.sh" "$install_dir"

jar="$root/target/GhidraMCP.jar"
props="$root/target/classes/extension.properties"
manifest="$root/target/classes/Module.manifest"
for f in "$jar" "$props" "$manifest"; do
    [ -f "$f" ] || { echo "error: $f not found -- run ./scripts/build.sh first" >&2; exit 1; }
done

built_version="$(sed -n 's/^ghidraVersion=//p' "$props" | tr -d '\r')"
if [ "$built_version" != "$GHIDRA_VERSION" ]; then
    echo "error: built for Ghidra '$built_version' but installing into $GHIDRA_VERSION" >&2
    echo "       rebuild with ./scripts/build.sh $GHIDRA_INSTALL_DIR" >&2
    exit 1
fi

dest="$GHIDRA_EXT_DIR/GhidraMCP"
if [ -e "$dest" ]; then
    backup="$dest.bak.$$"
    mv "$dest" "$backup"
    echo "moved existing install to $backup"
fi
mkdir -p "$dest/lib"

cp "$props" "$dest/extension.properties"
cp "$manifest" "$dest/Module.manifest"

if [ "$mode" = link ]; then
    ln -sf "$jar" "$dest/lib/GhidraMCP.jar"
    ln -sf "$root/bridge_mcp_ghidra.py" "$dest/bridge_mcp_ghidra.py"
else
    cp "$jar" "$dest/lib/GhidraMCP.jar"
    cp "$root/bridge_mcp_ghidra.py" "$dest/bridge_mcp_ghidra.py"
fi

echo "installed ($mode) to $dest"
echo "restart Ghidra $GHIDRA_VERSION, then enable GhidraMCPPlugin in File -> Configure -> Developer"
