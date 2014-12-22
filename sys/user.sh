#!/bin/sh

MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

# find root
cd `dirname $PWD/$0` ; cd ..

# update
if [ "$1" != "--without-pull" ]; then
	if [ -d .git ]; then
		git branch | grep "^\* master" > /dev/null
		if [ $? = 0 ]; then
			echo "WARNING: Updating from remote repository"
			git pull
		fi
	fi
else
	shift
fi

if [ -z "${HOME}" ]; then
	echo "HOME not set"
	exit 1
fi

if [ ! -d "${HOME}" ]; then
	echo "HOME is not a directory"
	exit 1
fi

ROOT=${HOME}/.radare2-prefix

if [ "${HARDEN}" = 1 ]; then
	./sys/build-harden.sh ${ROOT} && ${MAKE} symstall
else
	./sys/build.sh ${ROOT} && ${MAKE} symstall
fi
${MAKE} user-install
echo
echo radare2 is now installed in ~/.radare2-prefix
echo
echo Now add ${HOME}/bin to your ${PATH}
echo
