#!/bin/sh
make -C dist/tarball
cp -f dist/tarball/*.zip .
cp -f dist/tarball/*.xz .
