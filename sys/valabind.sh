#!/bin/sh

# find root
cd `dirname $PWD/$0`

mkdir  _work
cd _work || exit 1
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
