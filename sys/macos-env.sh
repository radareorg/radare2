#!/bin/sh

export PATH=$(pwd)/sys:${PATH}
export CC=$(pwd)/sys/macos-sdk-clang
export CFLAGS="-Oz -DNDEBUG"
