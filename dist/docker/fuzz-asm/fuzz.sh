#!/bin/bash


args() {
	OP="$1"
	ARGS=""
	NARGS=$(($RANDOM%4))
	while : ; do
		[ "$NARGS" = 0 ] && break
		TYPE=$(($RANDOM%4))
		case "$TYPE" in
		0)
			ARGS="$ARGS $RANDOM"
			;;
		1)
			ARGS="$ARGS r$RANDOM"
			;;
		2)
			ARGS="$ARGS 0x$RANDOM"
			;;
		3)
			ARGS="$ARGS -$RANDOM"
			;;
		esac
		NARGS=$(($NARGS-1))
		COMMA=$(($RANDOM%2))
		[ "$COMMA" = 1 ] && ARGS="$ARGS ,"
	done
	echo "$OP $ARGS"
}

[ -z "$R2_ARCH" ] && R2_ARCH=x86
[ -z "$R2_BITS" ] && R2_BITS=32

if [ -z "${OPS}" ]; then
	OPS=`r2 -qc aoml --`
	if [ -z "${OPS}" ]; then
		OPS="r2 -a $R2_ARCH -b $R2_BITS -qc'wR;piD~!invalid' -"
		if [ -z "${OPS}" ]; then
			OPS="mov push jmp call ret"
		fi
	fi
fi
for a in ${OPS} ; do
	LINE=`args $a`
	echo "INPUT=$LINE" > /dev/stderr
	rasm2 -a $R2_ARCH -b $R2_BITS "$LINE"
done
