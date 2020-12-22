#!/bin/sh

git clone https://github.com/radareorg/radare2-extras
cd radare2-extras
./configure --prefix=/usr
make
sudo make symstall
