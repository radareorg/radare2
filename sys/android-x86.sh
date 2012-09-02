#!/bin/sh
cd `dirname $PWD/$0`
export CFLAGS="-O3"
./android-shell.sh x86 ./android-build.sh x86
