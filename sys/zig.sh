#!/bin/sh

# cross compile to linux-arm64
#export CC="zig cc -target aarch64-linux"
export CC="zig cc -std=c11"
export LD="zig cc"
export AR="zig ar"
export RANLIB="zig ranlib"
./configure --without-threads
make -j
