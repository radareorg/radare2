#!/bin/sh
LD=/etc/ld.so.conf.d
type ldconfig > /dev/null 2>&1
if [ $? = 0 ]; then
	mkdir -p $LD
	awk -F= '/^LIBDIR/{print $2}' config-user.mk > $LD/radare.conf
	ldconfig
fi
