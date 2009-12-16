#!/bin/sh
MOD=r_util
CFLAGS="-I ../libr/include -I /usr/include/python2.5"
export CFLAGS
swig -python ${MOD}.i 
gcc -shared ${MOD}_wrap.c ${CFLAGS} -o _${MOD}.so ../libr/util/*.o
