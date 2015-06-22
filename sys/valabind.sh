#!/bin/sh

[ -z "${PREFIX}" ] && PREFIX=/usr

# find root
cd "$(dirname "$PWD/$0")"
. ./CONFIG

mkdir  _work
cd _work || exit 1
if [ -d valabind ]; then
	cd valabind
	git pull
else
    if [ -z "${USE_GIT_URLS}" ]; then
    	git clone https://github.com/radare/valabind
    else
    	git clone git://github.com/radare/valabind
    fi
	cd valabind
fi

make clean
make
sudo make install PREFIX=${PREFIX}
