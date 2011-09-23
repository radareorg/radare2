#!/bin/sh

# find root
cd `dirname $PWD/$0` ; cd ..

. ./farm/CONFIG

if [ -z "${REMOTEDIR}" ]; then
	echo "# You have to setup the REMOTEDIR var in your config var"
	echo "echo 'REMOTEDIR=user@host:/path/remote/dir' > ~/.r2farmrc"
	exit 1
fi

echo rsync -avz farm/log/ ${REMOTEDIR}
rsync -avz farm/log/ ${REMOTEDIR}
