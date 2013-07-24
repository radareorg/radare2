#!/bin/sh

# find root
cd `dirname $(pwd)/$0`

mkdir -p _work
cd _work

if [ -d gtkaml ]; then
	cd gtkaml
	svn up
else
	svn co https://gtkaml.googlecode.com/svn/trunk gtkaml
	cd gtkaml
fi
sh autogen.sh --prefix=/usr && \
make && \
sudo make install
