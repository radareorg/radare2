#!/bin/sh

MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

${MAKE} --help 2>&1 | grep gnu > /dev/null
if test $? != 0
then
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
                        echo git pull
                fi
fi # wat ?
else
        shift
fi

# su OR sudo
type sudo || NOSUDO=1

[ "$(id -u)" = 0 ] || SUDO="sudo \"${MAKE} ${INSTALL_TARGET}\""
[ -n "${NOSUDO}" ] && SUDO='/bin/su -m root -c ${MAKE} ${INSTALL_TARGET}'
if [ "${M32}" = 1 ]; then
        ./sys/build-m32.sh $* && ${SUDO}
elif [ "${HARDEN}" = 1 ]; then
        # shellcheck disable=SC2048
        # shellcheck disable=SC2086
        ./sys/build-harden.sh $* && ${SUDO}
else
        # shellcheck disable=SC2048
        # shellcheck disable=SC2086
echo DUMP: ${SUDO}
        ./sys/build.sh $* && ${SUDO}
fi
