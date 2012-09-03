DESTDIR?=
PREFIX?=/usr

VERSION=0.5

CFLAGS+=-DVERSION=\"${VERSION}\"

CFLAGS+=-Wall
#CFLAGS+=-O3
#CFLAGS+=-ggdb -g -Wall -O0

HAVE_VALA=$(shell valac --version)
