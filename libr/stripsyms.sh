#!/bin/sh

# skip this thing. it slow downs the build too much
exit 0

[ -n "${NOSTRIP}" ] && exit 0

[ -z "$2" ] && exit 0
FILE=$1
PFX=$2
LIST=$1.list

if [ "${PFX}" = "r_util" ]; then
	echo "=> No stripping any symbol in libr_util O:)"
	exit 0
	PFX="r_"
fi

nm --defined-only -B ${FILE} 2>/dev/null | grep -v ^${PFX}_ | awk '{print $3}' > ${LIST}
#if [ -n "`cat /tmp/list`" ]; then
echo "STRIP ${FILE}"
objcopy --strip-symbols ${LIST} ${FILE} 2>/dev/null
#TODO: Uncomment on release
#strip -s ${FILE}
#fi

rm -f ${LIST}
