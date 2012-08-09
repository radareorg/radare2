#!/bin/sh

# find root
cd `dirname $PWD/$0` ; cd ..

. ./sys/CONFIG
cat sys/CONFIG

export PYTHON
export PYTHON_VERSION
export PYTHON_CONFIG
echo "Using PYTHON_VERSION ${PYTHON_VERSION}"
PYTHON_CONFIG="python${PYTHON_VERSION}-config"
echo "Using PYTHON_CONFIG ${PYTHON_CONFIG}"
echo

cd r2-bindings
./configure --prefix=/usr --enable-devel --enable=python || exit 1
sudo make install-vapi || exit 1
cd python
make clean
make PYTHON=${PYTHON}
[ ! "$1" = --no-install ] && \
	sudo make install PYTHON=${PYTHON} PYTHON_VERSION=${PYTHON_VERSION}
