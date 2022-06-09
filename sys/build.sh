#!/bin/sh

OSNAME=$(uname)

. `dirname $0`/make-jobs.inc.sh

if [ -z "${MAKE}" ]; then
	MAKE=make
	gmake --help >/dev/null 2>&1
	[ $? = 0 ] && MAKE=gmake
fi

[ -z "${CERTID}" ] && CERTID=org.radare.radare2

# find root
A=$(dirname "$PWD/$0")
cd "$A" && cd .. || exit 1

DEFAULT_PREFIX=/usr/local
if [ "${OSNAME}" = Darwin ]; then
	# purge previous installations on other common paths
	if [ -f /usr/bin/r2 ]; then
		type sudo || NOSUDO=1
		[ "$(id -u)" = 0 ] || SUDO=sudo
		[ -n "${NOSUDO}" ] && SUDO=
	fi
fi

[ -z "${PREFIX}" ] && PREFIX="${DEFAULT_PREFIX}"

for a in $* ; do
	case "$a" in
	-h|--help)
		echo "Usage: sys/build.sh [/usr/local]"
		exit 0
		;;
	'')
		:
		;;
	--**|-)
		shift
		CFGARG="${CFGARG} $a"
		;;
	*)
		PREFIX="$a"
		;;
	esac
done

if [ "${USE_CS4}" = 1 ]; then
	CFGARG="${CFGARG} --with-capstone4"
fi

if [ "${OSNAME}" = Linux ] && [ -n "${PREFIX}" ] && [ "${PREFIX}" != /usr ]; then
	CFGARG="${CFGARG} --with-rpath"
fi

ccache --help > /dev/null 2>&1
if [ $? = 0 ]; then
	[ -z "${CC}" ] && CC=gcc
	CC="ccache ${CC}"
	export CC
fi

# Required to build on FreeBSD
if [ ! -x /usr/bin/gcc ] && [ -x /usr/bin/cc ]; then
	export CC=cc
	export HOST_CC=cc
fi

# purge first
if [ "${PREFIX}" != "/usr" ]; then
	A=$(readlink /usr/bin/radare2 2>/dev/null)
	B="${PWD}/binr/radare2/radare2"
	if [ -n "$A" ] && [ ! -f "$A" ]; then
		A="$B"
	fi
	if [ "$A" = "$B" ]; then
		echo "Purging r2 installation from /usr..."
		./configure --prefix=/usr > /dev/null
		echo ${SUDO} ${MAKE} uninstall
		SD=""
		type sudo && SD=sudo
		${SD} ${MAKE} uninstall
	fi
fi

# build
${MAKE} mrproper > /dev/null 2>&1
[ "${OSNAME}" = Linux ] && export LDFLAGS="-Wl,--as-needed ${LDFLAGS}"
[ -z "${KEEP_PLUGINS_CFG}" ] && rm -f plugins.cfg
unset R2DEPS
pwd

./configure ${CFGARG} --prefix="${PREFIX}" || exit 1
${MAKE} -s -j${MAKE_JOBS} MAKE_JOBS=${MAKE_JOBS} || exit 1
if [ "${OSNAME}" = Darwin ]; then
	./sys/macos-cert.sh
	${MAKE} macos-sign macos-sign-libs CERTID="${CERTID}" || (
		echo "CERTID not defined. If you want the bins signed to debug without root"
		echo "follow the instructions described in doc/macos.md and run make macos-sign."
	)
fi
