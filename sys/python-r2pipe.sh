#!/bin/sh

cd "$(dirname "$PWD/$0")"
./clone-r2-bindings.sh
cd ..

. ./sys/CONFIG
echo "============="
cat sys/CONFIG
echo "============="
cd radare2-bindings
cd r2pipe/python
${SUDO} make install
