#!/bin/sh

MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

${MAKE} --help 2>&1 | grep -q gnu
if [ $? != 0 ]; then
	echo "You need GNU Make to build me"
	exit 1
fi

# find root
cd "$(dirname "$0")" ; cd ..

export WITHOUT_PULL=0
ROOT=

abspath() {
	echo "$1" | grep -q ^/
	if [ $? = 0 ]; then
		echo "$1"
	else
		echo "`pwd`/$1"
	fi
}

while [ $# -gt 0 ]
do
	case "$1" in
		"--without-pull")
			WITHOUT_PULL=1
			;;
		"--install-path")
			shift
			if [ -n "$1" ]; then
				ROOT="`abspath $1`"
				BINDIR="$ROOT/bin"
			else
				echo "ERROR: install-path must not be empty"
				exit 1
			fi
			;;
		*)
			echo "WARNING: unknown argument \"$1\""
	esac
	shift
done

# update
if [ $WITHOUT_PULL -eq 0 ]; then
	if [ -d .git ]; then
		git branch | grep "^\* master" > /dev/null
		if [ $? = 0 ]; then
			echo "WARNING: Updating from remote repository"
			git pull
		fi
	fi
fi

if [ -z "${ROOT}" ]; then
	if [ -z "${HOME}" ]; then
		echo "HOME not set"
		exit 1
	fi

	if [ ! -d "${HOME}" ]; then
		echo "HOME is not a directory"
		exit 1
	fi
	ROOT="${HOME}/bin/prefix/radare2"
	BINDIR="${HOME}/bin"
fi

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
echo "radare2 is now installed in ${BINDIR}"
echo
echo "Now add ${BINDIR} to your PATH"
echo
