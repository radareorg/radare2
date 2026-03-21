#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
FILC_DIR="$ROOT/sys/filc"
FILC_VERSION=${FILC_VERSION:-0.678}
FILC_NAME="filc-${FILC_VERSION}-linux-x86_64"
FILC_ROOT=${FILC_ROOT:-$FILC_DIR/$FILC_NAME}

if [ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]; then
	echo "filc only supports linux-amd64, falling back to Docker..."
	docker build -t r2filc -f "$FILC_DIR/Dockerfile" "$FILC_DIR"
	exec docker run --rm -v "$ROOT:/r2" -w /r2 r2filc ./sys/filc.sh "$@"
fi

command -v filcc || [ -x "$FILC_ROOT/build/bin/filcc" ] || {
	mkdir -p "$FILC_DIR"
	[ -f "$FILC_DIR/$FILC_NAME.tar.xz" ] || \
		curl -L --fail -o "$FILC_DIR/$FILC_NAME.tar.xz" \
		"https://github.com/pizlonator/fil-c/releases/download/v${FILC_VERSION}/${FILC_NAME}.tar.xz"
	[ -d "$FILC_ROOT" ] || \
		tar -C "$FILC_DIR" -xf "$FILC_DIR/$FILC_NAME.tar.xz"
}

[ ! -x "$FILC_ROOT/setup.sh" ] || [ -L "$FILC_ROOT/pizfix/os-include/linux" ] || (cd "$FILC_ROOT" && ./setup.sh)

if [ -d "$FILC_ROOT/pizfix/lib" ] && command -v cc; then
	for obj in Scrt1.o crtbegin.o crtend.o crti.o crtn.o; do
		dst="$FILC_ROOT/pizfix/lib/$obj"
		[ -e "$dst" ] && continue
		src=$(cc -print-file-name="$obj" || true)
		[ -n "$src" ] && [ "$src" != "$obj" ] && [ -e "$src" ] && ln -s "$src" "$dst"
	done
fi

FILC_BIN=$(dirname "$(command -v filcc || echo "$FILC_ROOT/build/bin/filcc")")
export PATH="$FILC_BIN:$PATH" CC=filcc USERCC=filcc HOST_CC=${HOST_CC:-cc}

[ -z "${MAKE:-}" ] && MAKE=make
cd "$ROOT"
. ./sys/make-jobs.inc.sh
${MAKE} mrproper || true
[ -z "${KEEP_PLUGINS_CFG:-}" ] && rm -f plugins.cfg
./configure --with-rpath "$@" || exit 1
${MAKE} -j || exit 1
