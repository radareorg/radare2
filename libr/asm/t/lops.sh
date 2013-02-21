#!/bin/sh
a=0
b=0
arch=$1
[ -z "$arch" ] && arch=x86
while : ; do
	x=`printf "%02x%02x000000000" $b $a`
	printf "$x  "
	rasm2 -e -a $arch -d $x 2>/dev/null | head -n1
	if [ "$a" = 255 ]; then
		a=0
		b=$(($b+1))
		[ "$b" = 256 ] && break
	else
		a=$(($a+1))
	fi
done
