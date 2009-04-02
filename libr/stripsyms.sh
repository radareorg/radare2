#!/bin/sh
[ -z "$2" ] && exit 0
FILE=$1
PFX=$2
LIST=$1.list

if [ "${PFX}" = "r_util" ]; then
	PFX="r_"
fi

nm --defined-only -B ${FILE} | grep -v ${PFX}_ | awk '{print $3}' > ${LIST}
#if [ -n "`cat /tmp/list`" ]; then
echo "=> Stripping unnecessary symbols for ${FILE}..."
objcopy --strip-symbols ${LIST} ${FILE}
#TODO: Uncomment on release
#strip -s ${FILE}
#fi

rm -f ${LIST}
