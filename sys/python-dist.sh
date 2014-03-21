#!/bin/sh
cd `dirname $PWD/$0`
./python.sh --no-install
./clone-r2-bindings.sh
cd ../radare2-bindings
make dist
