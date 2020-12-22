#!/bin/sh
# Sets up env for programs that use r2 libs, and r2 is installed in a
# non-standard location.

export PKG_CONFIG_PATH="`r2 -H R2_LIBDIR`/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
export LD_LIBRARY_PATH="`r2 -H R2_LIBDIR`${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
