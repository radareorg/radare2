#!/bin/sh

# cross compile to linux-arm64
#export CC="zig cc -target aarch64-linux"
export CC="zig cc"
./configure
make -j
