#!/bin/sh

# find root
cd `dirname $PWD/$0` ; cd ..

D=${PWD}/prefix-install
P=`./configure --version|head -n 1|cut -d ' ' -f 1`
rm -rf $D
mkdir $D
make install DESTDIR=$D
cd $D
tar czvf ../$P-bin.tar.gz *
rm -rf $D
