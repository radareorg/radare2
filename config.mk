VERSION=0.1
RELEASE=0
DESTDIR=
OSTYPE=gnulinux

COMPILER=gcc
#COMPILER=tcc

ifeq (${RELEASE},1)
PREFIX=/usr/local
else
PREFIX=${PWD}/prefix
VERSION=`date '+%Y%m%d'`
endif
