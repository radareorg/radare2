#!/data/data/com.termux/files/usr/bin/bash
bash ./configure --with-compiler=termux --prefix=/data/data/com.termux/files/usr
make -j2
make symstall
