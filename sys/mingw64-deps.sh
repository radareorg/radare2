#!/bin/sh

# find root
cd `dirname $PWD/$0`

mkdir -p _work
cd _work
# open http://mingw-w64.sourceforge.net/
if [ `uname` = Linux ]; then
	wget http://switch.dl.sourceforge.net/project/mingw-w64/Toolchains%20targetting%20Win64/Automated%20Builds/mingw-w64-bin_i686-linux_20110627.tar.bz2
	mkdir -p mingw64
	tar xjvf mingw-w64*.bz2 -C mingw64
	echo "export PATH=$PWD/mingw64/bin:$PATH"
else
	echo "Cannot install mingw64 for this platform"
	exit 1
fi
