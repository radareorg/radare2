#!/bin/sh
set -eu

cflags=$(pkg-config --cflags r_core)
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM
mkdir "$tmpdir/openssl"
# Reject transitive OpenSSL includes even when its development headers are installed.
for header in bn ssl err; do
	printf '#error Public radare2 headers must not require OpenSSL headers\n' > "$tmpdir/openssl/$header.h"
done

for language in c c++; do
	if [ "$language" = c ]; then
		compiler=${CC:-cc}
	else
		compiler=${CXX:-c++}
	fi
	printf '%s\n' \
		'#include <r_util/r_big.h>' \
		'#include <r_core.h>' \
		'#if !HAVE_LIB_SSL' \
		'#error This test requires an OpenSSL-enabled radare2 build' \
		'#endif' \
		'int main(void) { RNumBig *big = 0; RSocket socket; (void)big; (void)socket; return 0; }' \
		| $compiler -I"$tmpdir" $cflags -x "$language" -fsyntax-only -
done
