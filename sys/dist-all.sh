#!/bin/sh
cd `dirname $PWD/$0`/..

sys/clone-r2-bindings.sh
sys/install.sh
make dist

cd radare2-bindings
./configure --prefix=/usr --enable-devel
make mrproper
cd python
make
cd ..
make dist

DD=/tmp/r2
rm -rf $DD
mkdir -p $DD
cp ../radare2-bindings-`make version`.tar.gz $DD
cd ..
cp ../radare2-`make version`.tar.gz $DD
echo distribution tarballs have been copied to $DD
