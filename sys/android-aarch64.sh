#!/bin/sh
cd `dirname $PWD/$0`
export CFLAGS="-O3"
./android-shell.sh aarch64 ./android-build.sh aarch64-static
