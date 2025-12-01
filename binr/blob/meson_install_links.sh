#!/bin/sh
set -e

mkdir -p "${DESTDIR}/${MESON_INSTALL_PREFIX}/bin"
cd "${DESTDIR}/${MESON_INSTALL_PREFIX}/bin"

TOOLS="rahash2 rarun2 rasm2 rabin2 ragg2 r2agent radiff2 rafind2 rassign2 rax2 r2 radare2"

for TOOL in $TOOLS ; do
    ln -sf r2blob.static $TOOL ;
done
