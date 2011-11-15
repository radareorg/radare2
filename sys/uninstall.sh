#!/bin/sh

# find root
cd `dirname $PWD/$0` ; cd ..

MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

${MAKE} purge
${MAKE} deinstall
