#!/bin/sh
cd `dirname $(pwd)/$0`

D=$(pwd)/../prefix-install
./python.sh --no-install
cd ../r2-bindings
P=`./configure --version|head -n 1|cut -d ' ' -f 1`
sudo make install-vapi DESTDIR=$D
cd python
sudo make install DESTDIR=$D
cd $D
tar czvf ../$P-bin.tar.gz *
sudo rm -rf $D
