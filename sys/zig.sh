#!/bin/sh

#export CC="zig cc -std=c11"
#export LD="zig cc"

# cross compile to linux-arm64
export CC="zig cc -target aarch64-linux -Oz"
export LD="zig cc -target aarch64-linux -Oz"
export EXT_SO=so
export AR="zig ar"
export RANLIB="zig ranlib"
# ./configure --host=aarch64-gnu-linux --with-ostype=linux
rm -f libr/include/r_version.h
./configure --with-ostype=gnulinux
time make -j EXT_SO=so
