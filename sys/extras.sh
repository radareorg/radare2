#!/bin/sh

if [ -z "$USE_GIT_URLS" ]; then
    git clone https://github.com/radare/radare2-extras
else
    git clone git://github.com/radare/radare2-extras
fi

cd radare2-extras
./configure --prefix=/usr
make
sudo make symstall
