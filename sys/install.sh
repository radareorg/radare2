#!/bin/sh

MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

${MAKE} --help 2>&1 | grep -q gnu
if [ $? != 0 ]; then
	echo "You need GNU Make to build me"
	exit 1
fi

export MAKE="$MAKE"

[ -z "${INSTALL_TARGET}" ] && INSTALL_TARGET=symstall

# find root
cd "$(dirname "$0")" ; cd ..

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

export NOSUDO
if [ -n "${NOSUDO}" ]; then
	SUDO=""
else
	type sudo > /dev/null 2>&1 || NOSUDO=1
	SUDO=sudo
	[ -n "${NOSUDO}" ] && SUDO=
fi

if [ "$(id -u)" = 0 ]; then
	SUDO=""
else
	[ -n "${NOSUDO}" ] && SUDO="echo NOTE: sudo not found. Please run as root: "
fi

if [ "${M32}" = 1 ]; then
	./sys/build-m32.sh $* && ${SUDO} ${MAKE} ${INSTALL_TARGET}
elif [ "${HARDEN}" = 1 ]; then
	# shellcheck disable=SC2048
	# shellcheck disable=SC2086
	./sys/build-harden.sh $* && ${SUDO} ${MAKE} ${INSTALL_TARGET}
else
	# shellcheck disable=SC2048
	# shellcheck disable=SC2086
	./sys/build.sh $* && ${SUDO} ${MAKE} ${INSTALL_TARGET}
fi
