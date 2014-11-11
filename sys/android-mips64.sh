#!/bin/sh
cd `dirname $PWD/$0`
export CFLAGS="-O3 -fPIC -pie -fpic"
./android-shell.sh mips64 ./android-build.sh mips64-static
