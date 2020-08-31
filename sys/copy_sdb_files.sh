#!/bin/sh

SRC="$1"
DST="${DESTDIR}/${MESON_INSTALL_PREFIX}/$2"
mkdir -p "${DST}"
cp -fv "${SRC}"/*.sdb "${DST}"
