#!/bin/sh

MAKE=make
export CFLAGS="${CFLAGS} -fPIC"
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
PREFIX="${HOME}/.local"

abspath() {
	echo "$1" | grep -q ^/
	if [ $? = 0 ]; then
		echo "$1"
	else
		echo "`pwd`/$1"
	fi
}

ARGS=""
while [ $# -gt 0 ]
do
	case "$1" in
	"--without-pull")
		WITHOUT_PULL=1
		;;
	"--install-path")
		shift
		if [ -n "$1" ]; then
			PREFIX="`abspath $1`"
			BINDIR="$PREFIX/bin"
		else
			echo "ERROR: install-path must not be empty"
			exit 1
		fi
		;;
	*)
		ARGS="${ARGS} $1"
		;;
	esac
	shift
done

ARGS="${ARGS} --with-rpath"

# update
if [ $WITHOUT_PULL -eq 0 ]; then
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

if [ -z "${PREFIX}" ]; then
	if [ -z "${HOME}" ]; then
		echo "HOME not set"
		exit 1
	fi
	if [ ! -d "${HOME}" ]; then
		echo "HOME is not a directory"
		exit 1
	fi
	PREFIX="${HOME}/.local"
	# PREFIX="${PREFIX}/bin/prefix/radare2"
fi

if [ -z "${BINDIR}" ]; then
	BINDIR="${PREFIX}/bin"
fi

mkdir -p "${PREFIX}/lib"

if [ "${M32}" = 1 ]; then
	./sys/build-m32.sh "${PREFIX}" ${ARGS} && ${MAKE} symstall
elif [ "${HARDEN}" = 1 ]; then
	./sys/build-harden.sh "${PREFIX}" ${ARGS} && ${MAKE} symstall
else
	./sys/build.sh "${PREFIX}" ${ARGS} && ${MAKE} symstall
fi
if [ $? != 0 ]; then
	echo "Oops"
	exit 1
fi
${MAKE} symstall
S='$'
echo
echo "radare2 is now installed in ${PREFIX}"
echo
echo "export PATH=${BINDIR}:${S}PATH"
echo
