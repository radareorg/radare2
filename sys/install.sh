#!/bin/sh

# find
cd "$(dirname $0)"/..
CWD="`pwd`"

sudosetup() {
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

	if [ "${NOSUDO}" != 1 ]; then
		if [ "$(id -u)" = 0 ]; then
			SUDO=""
		else
			if [ -d /system/bin ]; then
				# This is an android
				SUDO=""
			else
				[ -n "${NOSUDO}" ] && SUDO="echo NOTE: sudo not found. Please run as root: "
			fi
		fi

		if [ "${USE_SU}" = 1 ]; then
			SUDO="/bin/su -m root -c"
		fi
	fi
}

sudosetup

echo "$CWD" | grep -q ' '
if [ $? = 0 ]; then
	USEMESON=1
fi
if [ "$USEMESON" = 1 ]; then
	rm -rf b
	meson b
	ninja -C b
	${SUDO} make symstall PWD="$PWD/b" BTOP="$PWD/b/binr"
	exit $RV
fi

export PAGER=cat
unset LINK

if [ "${SHELL}" = "/data/data/com.termux/files/usr/bin/bash" ]; then
    echo "Termux environment detected. Installing necessary packages"  
    pkg update -y && pkg install git build-essential binutils pkg-config -y
    ${PWD}/sys/termux.sh
    exit $?
fi

if [ "$(uname)" = "Haiku" ]; then
	gcc-x86 --version > /dev/null 2>&1
	if [ $? = 0 ]; then
		export CC=gcc-x86
		export HOST_CC=gcc-x86
		export USERCC=gcc-x86
	else
		echo "If compilation fails, install gcc-x86 from depot"
	fi
	export PREFIX="${PWD}/prefix"

else
	if [ "$(id -u)" = 0 ]; then
		echo "[WW] Do not run this script as root!"
		if [ -n "${SUDO_USER}" ]; then
			echo "[--] Downgrading credentials to ${SUDO_USER}"
			exec sudo -u "${SUDO_USER}" sys/install.sh $*
		fi
	fi
fi

echo "$PWD" | grep -q " "
if [ $? = 0 ]; then
	echo "You can't build radare from a directory with spaces with make" >&2
	echo "To solve this you must 'meson' instead" >&2
	exit 1
fi

export WANT_V35=0

export USE_CS4=0
export USE_CSNEXT=0
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
		;;
	"--install")
		export INSTALL_TARGET="install"
		;;
	"--without-pull")
		export WITHOUT_PULL=1
		;;
	'--prefix='*)
		PREFIX=`echo "$1" | cut -d = -f 2`
		ARGS="${ARGS} $1"
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

if [ -z "${MAKE}" ]; then
	MAKE=make
	gmake --help >/dev/null 2>&1
	[ $? = 0 ] && MAKE=gmake
	${MAKE} --help 2>&1 | grep -q gnu
	if [ $? != 0 ]; then
		echo "You need GNU Make to build me"
		exit 1
	fi
	export MAKE="$MAKE"
fi

[ -z "${INSTALL_TARGET}" ] && INSTALL_TARGET=symstall

# update
if [ -z "$WITHOUT_PULL" ]; then
	# if .git is a directory, that's a clone, if it's a file it's a submodule
	if [ -e .git ]; then
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


${SHELL} --version 2> /dev/null | grep -q fish
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

# handle home installations of capstone via r2pm
export PKG_CONFIG_PATH="${HOME}/.local/share/radare2/prefix/lib/pkgconfig/"
if [ -d "$HOME/.local/share/radare2/prefix/include/capstone" ]; then
	# capstone's pkg-config is wrong :_____
	# export CFLAGS="$(pkg-config --cflags capstone)"
	# export LDFLAGS="$(pkg-config --libs capstone)"
	export CFLAGS="-I$HOME/.local/share/radare2/prefix/include"
	export LDFLAGS="-L$HOME/.local/share/radare2/prefix/lib"
fi

NEED_CAPSTONE=1
pkg-config --cflags capstone > /dev/null 2>&1
if [ $? = 0 ]; then
	pkg-config --atleast-version=5.0.0 capstone >/dev/null 2>&1
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
	if [ ! -d shlr/capstone/.git -a ! -d .git ]; then
		NEED_CAPSTONE=0
	fi
fi

if [ "$NEED_CAPSTONE" = 1 ]; then
	if [ -d shlr/capstone ]; then
		${MAKE} -C shlr headsup 2> /dev/null || rm -rf shlr/capstone
	fi
	if [ ! -d shlr/capstone ]; then
		./preconfigure
	fi
fi
echo "ARGS=$ARGS"

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
