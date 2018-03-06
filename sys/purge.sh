#!/bin/sh

if [ -z "${MAKE}" ]; then
	 MAKE=make
	gmake --help >/dev/null 2>&1
	[ $? = 0 ] && MAKE=gmake
fi

if [ "$1" = "distro" ]; then
	# TODO: Query the user before taking any action
	if [ -x /usr/bin/apt-get ] ; then
		sudo apt-get remove radare2
		sudo apt-get remove libradare2-common
		sudo apt-get remove --auto-remove libradare2-common
		sudo apt-get purge libradare2-common
		sudo apt-get purge --auto-remove libradare2-common
		sudo apt-get remove libradare2
		sudo apt-get remove --auto-remove libradare2
		sudo apt-get purge libradare2
		sudo apt-get purge --auto-remove libradare2
	fi
	# TODO: support brew
	# TODO: support archlinux
	# TODO: support gentoo
	exit 0
fi

PREFIX="$1"
if [ -z "${PREFIX}" ]; then
	PREFIX=/usr
fi
[ -z "${SUDO}" ] && SUDO=sudo
echo "Uninstalling r2 from ${PREFIX}..."
./configure --prefix="${PREFIX}"
${SUDO} ${MAKE} purge2
