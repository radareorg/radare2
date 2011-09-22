#!/bin/sh

# find root
cd `dirname $PWD/$0` ; cd ..

# update
if [ -d .hg ]; then
	hg pull -u
elif [ -d .git ]; then
	git pull
fi

./sys/build.sh && sudo make symstall
