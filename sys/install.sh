#!/bin/sh

MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

# find root
cd `dirname $PWD/$0` ; cd ..

# update
if [ -d .hg ]; then
	hg pull -u
elif [ -d .git ]; then
	git pull
fi

[ "`id -u`" = 0 ] || SUDO=sudo
[ -n "${NOSUDO}" ] && SUDO=

if [ "${HARDEN}" = 1 ]; then
	./sys/build-harden.sh $@ && ${SUDO} ${MAKE} symstall
else
	./sys/build.sh $@ && ${SUDO} ${MAKE} symstall
fi
