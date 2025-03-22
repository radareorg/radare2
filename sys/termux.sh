#!/data/data/com.termux/files/usr/bin/bash

cd "$(dirname $0)"/..
pwd
unset LINK

if [ -z "${PREFIX}" ]; then
	echo "PREFIX env var not set, are you running this script from Termux?"
	PREFIX=/data/data/com.termux/files/usr
fi

export ANDROID=1
# make clean > /dev/null 2>&1
rm -f libr/include/r_version.h
cp -f dist/plugins-cfg/plugins.termux.cfg plugins.cfg
# Attempt to update from an existing remote
UPSTREAM_REMOTE=$(git remote -v | grep 'radareorg/radare2\(\.git\)\? (fetch)' | cut -f1 | head -n1)
if [ -n "$UPSTREAM_REMOTE" ]; then
	git pull "$UPSTREAM_REMOTE" master
else
	git pull https://github.com/radareorg/radare2 master
fi
./preconfigure
# ./configure-plugins
bash ./configure --with-compiler=termux --prefix=${PREFIX} || exit 1
make libr/include/r_version.h
touch -t 197001010000 libr/include/r_version.h
rm -f "${PREFIX}/lib/"libr_*
make -j2 || exit 1
make symstall
