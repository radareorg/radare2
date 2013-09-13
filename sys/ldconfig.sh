#!/bin/sh
LD=/etc/ld.so.conf.d
if test -w $LD ; then
	if type ldconfig > /dev/null 2>&1 ; then
		mkdir -p $LD
		P=$(awk -F= '/^LIBDIR/{print $2}' config-user.mk)
		D=`dirname $P`/`basename $P`
		if [ /usr != "$D" ]; then
			echo $P > $LD/radare.conf
			# do not update symlinks to avoid r2 install issues
			ldconfig -X
		fi
	fi
fi
exit 0
