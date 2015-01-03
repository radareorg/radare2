#!/bin/sh
PREFIX=/usr
MAKE=make
SUDO=sudo


# https://raw.githubusercontent.com/sroberts/peid4yara/master/peid.yar
#if [ ! -f shlr/yara/peid.yar ]; then
#(
#	cd shlr/yara
#	wget -c http://radare.org/get/peid.yar.gz
#	gunzip peid.yar.gz
#)
#fi

if [ ! -d yara ]; then
	git clone https://github.com/plusvic/yara.git || exit 1
fi
cd yara || exit 1
# working yara2 version
git reset --hard 880c268ce0b98046a476784c412d9e91573c8a08
sh bootstrap.sh
./configure --prefix=${PREFIX} || exit 1
${MAKE} CFLAGS=-DYYDEBUG=0 || exit 1
${SUDO} ${MAKE} install


if [ ! -d radare2-extras ]; then
	git clone https://github.com/radare/radare2-extras
fi

( cd radare2-extras
	./configure --prefix=/usr
	( cd yara/yara2
	./configure --prefix=/usr
	${MAKE}
	${SUDO} ${MAKE} symstall
	)
)
