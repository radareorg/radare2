#!/bin/sh
LD=/etc/ld.so.conf.d
if test -w $LD ; then
	if type ldconfig > /dev/null 2>&1 ; then
		mkdir -p $LD
		awk -F= '/^LIBDIR/{print $2}' config-user.mk > $LD/radare.conf
		ldconfig
	fi
fi
exit 0
