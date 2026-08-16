#!/bin/sh
# Resolve everything we need to know about a Ghidra installation.
#
# Sourced by the other scripts; not meant to be run directly. Sets:
#
#   GHIDRA_INSTALL_DIR   root of the install (contains Ghidra/, support/)
#   GHIDRA_VERSION       e.g. 11.4.1
#   GHIDRA_RELEASE       e.g. PUBLIC
#   GHIDRA_DIST          e.g. ghidra_11.4.1_PUBLIC
#   GHIDRA_JAVA_MIN      minimum JDK the install requires, e.g. 21
#   GHIDRA_USER_DIR      per-user settings dir for this exact version
#   GHIDRA_EXT_DIR       per-user extensions dir for this exact version
#
# Install dir is taken from, in order: $1, $GHIDRA_INSTALL_DIR, the "lastrun"
# file Ghidra writes on launch, then a few conventional locations.

ghidra_die() {
    echo "error: $*" >&2
    exit 1
}

ghidra_prop() {
    # ghidra_prop <file> <key>  -- read a key from a java .properties file
    sed -n "s/^$2=//p" "$1" | tr -d '\r' | head -1
}

ghidra_user_root() {
    case "$(uname -s)" in
        Darwin) echo "$HOME/Library/ghidra" ;;
        MINGW*|MSYS*|CYGWIN*) echo "${APPDATA:-$HOME/AppData/Roaming}/ghidra" ;;
        *) echo "${XDG_CONFIG_HOME:-$HOME/.config}/ghidra" ;;
    esac
}

ghidra_find_install() {
    if [ -n "$1" ]; then
        echo "$1"
        return
    fi
    if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
        echo "$GHIDRA_INSTALL_DIR"
        return
    fi

    # Ghidra records the install it was last launched from.
    lastrun="$(ghidra_user_root)/lastrun"
    if [ -f "$lastrun" ]; then
        dir="$(tr -d '\r\n' < "$lastrun")"
        if [ -f "$dir/Ghidra/application.properties" ]; then
            echo "$dir"
            return
        fi
    fi

    for dir in /Applications/ghidra_*_PUBLIC /opt/ghidra_*_PUBLIC \
               "$HOME"/ghidra_*_PUBLIC "$HOME"/Downloads/ghidra_*_PUBLIC; do
        [ -f "$dir/Ghidra/application.properties" ] && echo "$dir" && return
    done
}

GHIDRA_INSTALL_DIR="$(ghidra_find_install "${1:-}")"
[ -n "$GHIDRA_INSTALL_DIR" ] || ghidra_die \
    "no Ghidra install found. Pass one as an argument or set GHIDRA_INSTALL_DIR."

app_props="$GHIDRA_INSTALL_DIR/Ghidra/application.properties"
[ -f "$app_props" ] || ghidra_die \
    "$GHIDRA_INSTALL_DIR is not a Ghidra install (no Ghidra/application.properties)"

GHIDRA_VERSION="$(ghidra_prop "$app_props" application.version)"
GHIDRA_RELEASE="$(ghidra_prop "$app_props" application.release.name)"
GHIDRA_JAVA_MIN="$(ghidra_prop "$app_props" application.java.min)"
GHIDRA_JAVA_COMPILER="$(ghidra_prop "$app_props" application.java.compiler)"
[ -n "$GHIDRA_VERSION" ] || ghidra_die "could not read application.version from $app_props"
[ -n "$GHIDRA_RELEASE" ] || GHIDRA_RELEASE=PUBLIC

GHIDRA_DIST="ghidra_${GHIDRA_VERSION}_${GHIDRA_RELEASE}"
GHIDRA_USER_DIR="$(ghidra_user_root)/$GHIDRA_DIST"
GHIDRA_EXT_DIR="$GHIDRA_USER_DIR/Extensions"

export GHIDRA_INSTALL_DIR GHIDRA_VERSION GHIDRA_RELEASE GHIDRA_DIST \
       GHIDRA_JAVA_MIN GHIDRA_JAVA_COMPILER GHIDRA_USER_DIR GHIDRA_EXT_DIR
