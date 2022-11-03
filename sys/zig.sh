#!/bin/sh

export CC="zig cc -std=c11"
export LD="zig cc"

# cross compile to linux-arm64
#export CC="zig cc -std=c11 -target aarch64-linux"
#export LD="zig cc -target aarch64-linux"

export AR="zig ar"
export RANLIB="zig ranlib"
./configure
time make -j
