#!/bin/sh
# dependency checker -- pancake

deps="$@"
[ -z "$deps" ] && exit 0

getext() {
	u=$(grep OSTYPE ../../config-user.mk| head -n 1 | cut -d = -f 2)
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

a=0
count=3
cur=$(basename `pwd`)
while [ $a = 0 ] ; do
	a=1
	libs="$(echo $deps | sed -e s,r_,,g)"
	for l in $libs ; do
		if [ ! -f "../$l/libr_$l.$ext" ]; then
			echo "NOT FOUND r_$l"
			a=0
		fi
	done
	if [ $a = 0 ]; then
		echo "[$cur] waiting for $libs ($ext)"
		count=$(($count-1))
		if [ $count = 0 ]; then
			echo "[$cur] Compilation failed"
			#exit 1
		fi
		sleep 1
	fi
done
exit 0
