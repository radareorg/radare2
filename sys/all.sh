#!/bin/sh

# find root
cd `dirname $(pwd)/$0` ; cd ..

run() {
	[ ! -x sys/.mark_$1 ] && sys/$1.sh
}

run install
run python-deps
run python
