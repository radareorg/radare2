#!/bin/sh
cd `dirname $(pwd)/$0`

./python.sh --no-install
cd ../r2-bindings
make dist
