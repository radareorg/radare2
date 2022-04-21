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
	"--without-pull")
		export WITHOUT_PULL=1
		continue
		;;
	-*)
		# just for the penguin face case
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
if [ -z "$WITHOUT_PULL" ]; then
	if [ -d .git ]; then
		git branch | grep "^\* master" > /dev/null
		if [ $? = 0 ]; then
			echo "WARNING: Updating from remote repository"
			# Attempt to update from an existing remote
			UPSTREAM_REMOTE=$(git remote -v | grep 'radareorg/radare2\(\.git\)\? (fetch)' | cut -f1 | head -n1)
			if [ -n "$UPSTREAM_REMOTE" ]; then
				git pull "$UPSTREAM_REMOTE" master
			else
				git pull https://github.com/radareorg/radare2 master
			fi
		fi
	fi
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

NEED_CAPSTONE=1
pkg-config --cflags capstone 2>&1 > /dev/null
if [ $? = 0 ]; then
	pkg-config --atleast-version=5.0.0 capstone 2>/dev/null
	if [ $? = 0 ]; then
		pkg-config --variable=archs capstone 2> /dev/null | grep -q riscv
		if [ $? = 0 ]; then
			export CFGARG="--with-syscapstone"
			NEED_CAPSTONE=0
			echo "Note: Using system-wide-capstone"
		else
			echo "Warning: Your system-wide capstone dont have enough archs"
		fi
	else
		echo "Warning: Your system-wide capstone is too old for me"
	fi
else
	echo "Warning: Cannot find system wide capstone"
fi

if [ "$NEED_CAPSTONE" = 1 ]; then
	if [ ! -d shlr/capstone ]; then
		./preconfigure
	fi
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
