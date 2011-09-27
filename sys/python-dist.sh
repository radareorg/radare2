#!/bin/sh
cd `dirname $PWD/$0`

./python.sh --no-install
cd ../r2-bindings
make dist
