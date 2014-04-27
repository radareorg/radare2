#!/bin/sh
PREFIX=/usr
MAKE=make
SUDO=sudo

rm -rf yara
git clone https://github.com/plusvic/yara.git || exit 1
cd yara || exit 1
sh bootstrap.sh
./configure --prefix=${PREFIX} || exit 1
${MAKE} || exit 1
exec ${SUDO} ${MAKE} install
