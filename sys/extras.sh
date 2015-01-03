#!/bin/sh

git clone https://github.com/radare/radare2-extras
cd radare2-extras
./configure --prefix=/usr
make
sudo make symstall
