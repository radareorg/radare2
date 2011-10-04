#!/bin/sh

# find root
cd `dirname $PWD/$0`

mkdir -p _work
cd _work
if [ -d valabind ]; then
	cd valabind
	hg pull -u
else
	hg clone http://hg.youterm.com/valabind
	cd valabind
fi

make clean
make
sudo make install
