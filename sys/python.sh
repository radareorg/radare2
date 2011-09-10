#!/bin/sh

# find root
cd `dirname $PWD/$0` ; cd ..

. ./sys/CONFIG

export PYTHON_CONFIG

cd r2-bindings
./configure --prefix=/usr --enable-devel --enable=python
cd python
make clean
make
sudo make install
