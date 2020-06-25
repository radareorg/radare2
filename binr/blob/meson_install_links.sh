#!/bin/sh

mkdir -p "${DESTDIR}/${MESON_INSTALL_PREFIX}/bin"
pushd "${DESTDIR}/${MESON_INSTALL_PREFIX}/bin"
ln -sf radare2 rahash2
ln -sf radare2 rarun2
ln -sf radare2 rasm2
ln -sf radare2 rabin2
ln -sf radare2 ragg2
ln -sf radare2 r2agent
ln -sf radare2 radiff2
ln -sf radare2 rafind2
ln -sf radare2 rasign2
ln -sf radare2 rax2
ln -sf radare2 r2
popd
