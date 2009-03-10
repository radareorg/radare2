VERSION=0.1
RELEASE=0
DESTDIR=
OSTYPE=gnulinux

ifeq (${RELEASE},1)
PREFIX=/usr/local
else
PREFIX=${PWD}/prefix
VERSION=`date '+%Y%m%d'`
endif
