#!/bin/sh

MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

# find root
cd `dirname $PWD/$0` ; cd ..

# update
if [ -d .git ]; then
    echo "WARNING: Updating from remote repository"
    echo git pull
fi


# skip su or sudo
[ -z "${SUDO}" ] && ./sys/build.sh $@ && exit

if [ "${HARDEN}" = 1 ]
then
    ./sys/build-harden.sh $@ && ${SUDO} ${MAKE} symstall
else
if [ "${SUDO}" = 'su' ]
then
     ./sys/build.sh $@ && /bin/su -c "make symstall"
else
     ./sys/build.sh $@ && ${SUDO} ${MAKE} symstall
fi 
fi  
