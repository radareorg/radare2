#!/bin/sh
# dependency checker -- pancake

deps="$@"
[ -z "$deps" ] && exit 0

getext() {
	u=$(cat ../../config-user.mk| grep HOST_OS |cut -d = -f 2)
	case $u in
	windows)
		echo dll
		;;
	darwin)
		echo dylib
		;;
	#@*linux*)
	*)
		echo so
		;;
	esac
}; ext=$(getext)

cur=$(basename `pwd`)
a=0
while [ $a = 0 ] ; do
	a=1
	libs="$(echo $deps | sed -e s,r_,,g)"
	for l in $libs ; do
		if [ ! -f "../$l/libr_$l.$ext" ]; then
			a=0
		fi
	done
	if [ $a = 0 ]; then
		echo "[$cur] waiting for $libs"
		sleep 1
	fi
done
exit 0
