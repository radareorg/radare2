#!/bin/sh

# find root
cd `dirname $(pwd)/$0`

mkdir -p _work
cd _work
if [ -d valabind ]; then
	cd valabind
	git pull
else
	git clone git://github.com/radare/valabind
	cd valabind
fi

make clean
make
sudo make install
