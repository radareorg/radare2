#!/bin/sh

MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

# find root
cd `dirname $PWD/$0` ; cd ..

# update
if [ -d .git ]; then
	echo "WARNING: Updating from remote repository"
	git pull
fi

[ "`id -u`" = 0 ] || SUDO=sudo
[ -n "${NOSUDO}" ] && SUDO=

if [ "${HARDEN}" = 1 ] 
then
	./sys/build-harden.sh $@ && ${SUDO} ${MAKE} symstall
else 
if [ -n "${NOSUDO}" ]
then
	  ./sys/build.sh $@ && /bin/su -c "make symstall"
else
	./sys/build.sh $@ && ${SUDO} ${MAKE} symstall
fi
fi
