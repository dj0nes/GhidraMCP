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
backup=""
if [ -e "$dest" ]; then
    # A running Ghidra holds the installed jar open, and on Windows an open file
    # cannot be renamed or replaced. Find that out BEFORE touching anything, so a
    # locked install fails cleanly instead of leaving a half-moved extension dir.
    for old_jar in "$dest"/lib/*.jar; do
        [ -e "$old_jar" ] || [ -L "$old_jar" ] || continue
        if ! mv "$old_jar" "$old_jar.lockprobe" 2>/dev/null; then
            echo "error: $old_jar is locked (Ghidra is probably running)." >&2
            echo "       Close Ghidra and re-run; the existing install was not changed." >&2
            exit 1
        fi
        mv "$old_jar.lockprobe" "$old_jar"
    done

    # Keep the backup OUT of the extensions directory. Ghidra scans every
    # subdirectory there and parses each one as a module, so a "GhidraMCP.bak.NNN"
    # left in place is loaded as a second, duplicate extension and reports
    # manifest errors on every startup.
    backup_dir="$GHIDRA_EXT_DIR/../GhidraMCP-backups"
    mkdir -p "$backup_dir"
    backup="$backup_dir/GhidraMCP.bak.$$"
    mv "$dest" "$backup" || {
        echo "error: could not move $dest aside; the existing install was not changed." >&2
        exit 1
    }
    echo "moved existing install to $backup"

    # If anything below fails, put the old install back rather than leave a partial one.
    restore_backup() {
        status=$?
        if [ "$status" -ne 0 ] && [ -n "$backup" ] && [ -e "$backup" ]; then
            rm -rf "$dest"
            mv "$backup" "$dest" && echo "install failed; restored previous install from $backup" >&2
        fi
        exit "$status"
    }
    trap restore_backup EXIT
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

trap - EXIT
echo "installed ($mode) to $dest"
echo "restart Ghidra $GHIDRA_VERSION, then enable GhidraMCPPlugin in File -> Configure -> Developer"
