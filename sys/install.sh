#!/bin/sh

if [ "$(id -u)" = 0 ]; then
	echo "[WW] Do not run this script as root!"
	if [ -n "${SUDO_USER}" ]; then
		echo "[--] Downgrading credentials to ${SUDO_USER}"
		exec sudo -u "${SUDO_USER}" sys/install.sh $*
	fi
fi

export USE_CS4=0
# if owner of sys/install.sh != uid && uid == 0 { exec sudo -u id -A $SUDO_UID sys/install.sh $* }
ARGS=""
while : ; do
	[ -z "$1" ] && break
	case "$1" in
	--help)
		./configure --help
		echo
		echo "NOTE: Use sys/install.sh --install to use 'cp' instead of 'ln'."
		echo
		exit 0
		;;
	"--with-capstone4")
		export USE_CS5=1
		rm -rf shlr/capstone
		shift
		continue
		;;
	"--install")
		export INSTALL_TARGET="install"
		shift
		continue
		;;
	-*)
		# penguin face just for flags
		ARGS="${ARGS} $1"
		;;
	*)
		ARGS="${ARGS} $1"
		PREFIX="$1"
		;;
	esac
	shift
done

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

# find
cd "$(dirname $0)"/..
pwd

# update
if [ "$1" != "--without-pull" ]; then
	if [ -d .git ]; then
		git branch | grep "^\* master" > /dev/null
		if [ $? = 0 ]; then
			echo "WARNING: Updating from remote repository"
			git pull https://github.com/radareorg/radare2 master
		fi
	fi
else
	export WITHOUT_PULL=1
	shift
fi

umask 0002

export NOSUDO

if [ -w "${PREFIX}" ]; then
	NOSUDO=1
fi
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

if [ "${USE_SU}" = 1 ]; then
	SUDO="/bin/su -m root -c"
fi

${SHELL} --help 2> /dev/null | grep -q fish
if [ $? = 0 ]; then
	SHELL=/bin/sh
else
	# TCSH
	${SHELL} --help 2>&1 | grep -q vfork
	if [ $? = 0 ]; then
		SHELL=/bin/sh
		echo IS ASH
	fi
fi

if [ ! -d shlr/capstone ]; then
	./preconfigure
fi

if [ "${M32}" = 1 ]; then
	${SHELL} ./sys/build-m32.sh ${ARGS} || exit 1
elif [ "${HARDEN}" = 1 ]; then
	# shellcheck disable=SC2048
	# shellcheck disable=SC2086
	${SHELL} ./sys/build-harden.sh ${ARGS} || exit 1
else
	# shellcheck disable=SC2048
	# shellcheck disable=SC2086
	echo ${SHELL} ./sys/build.sh ${ARGS}
	pwd
	${SHELL} ./sys/build.sh ${ARGS} || exit 1
fi

${SUDO} ${MAKE} ${INSTALL_TARGET} || exit 1
if [ -z "${NOSUDO}" ]; then
	${SHELL} ./sys/ldconfig.sh
fi
