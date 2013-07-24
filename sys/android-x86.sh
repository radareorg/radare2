#!/bin/sh
cd `dirname $(pwd)/$0`
export CFLAGS="-O3"
./android-shell.sh x86 ./android-build.sh x86
