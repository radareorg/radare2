#!/bin/sh
cd `dirname $PWD/$0`

D=${PWD}/../prefix-install
./python.sh --no-install
cd ../r2-bindings
P=`./configure --version|head -n 1|cut -d ' ' -f 1`
sudo make install-vapi DESTDIR=$D
cd python
sudo make install DESTDIR=$D
cd $D
tar czvf ../$P-bin.tar.gz *
sudo rm -rf $D
