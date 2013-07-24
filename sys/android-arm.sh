#!/bin/sh
cd `dirname $(pwd)/$0`
export CFLAGS="-O3"
./android-shell.sh arm ./android-build.sh arm-static
