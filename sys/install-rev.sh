#!/bin/sh

if [ -z "$1" ]; then
	echo "Usage: install-rev [revision-number]"
	exit 1
fi
REV="$1"
MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

# find root
cd `dirname $PWD/$0` ; cd ..
echo hg up -C -r "${REV}"
hg up -C -r "${REV}"

./sys/build.sh && sudo ${MAKE} symstall
