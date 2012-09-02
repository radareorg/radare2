#!/bin/sh
cd `dirname $PWD/$0`
# PIC required for mips
export CFLAGS="-O3 -fPIC"
./android-shell.sh mips ./android-build.sh mips-static
