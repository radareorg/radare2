#!/bin/sh

MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

# find root
cd "$(dirname "$PWD/$0")" ; cd ..

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

ROOT="${HOME}/bin/prefix/radare2/"
mkdir -p "${ROOT}/lib"

if [ "${M32}" = 1 ]; then
	./sys/build-m32.sh "${ROOT}" && ${MAKE} symstall
elif [ "${HARDEN}" = 1 ]; then
	./sys/build-harden.sh "${ROOT}" && ${MAKE} symstall
else
	./sys/build.sh "${ROOT}" && ${MAKE} symstall
fi
if [ $? != 0 ]; then
	echo "Oops"
	exit 1
fi
${MAKE} user-install
echo
echo "radare2 is now installed in ${HOME}/bin"
echo
echo "Now add ${HOME}/bin to your PATH"
echo
