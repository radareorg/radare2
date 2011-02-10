#!/bin/sh
# Copyleft 2011
# Author: pancake(at)nopcode.org
# Wrapper for valaswig-cc

LNG=$1
MOD=$2
VALASWIGFLAGS="" ; [ 1 = "${DIST}" ] && VALASWIGFLAGS="-C"
if [ -z "${MOD}" ]; then
	echo "Usage: ./libr-swig.sh [python] [r_foo]"
	exit 1
fi
mkdir -p ${LNG}
cd ${LNG}

#valaswig-cc ${LNG} ${MOD} -I../../libr/include ../../libr/vapi/${MOD}.vapi -l${MOD} -L../../libr/$(echo ${MOD} | sed -e s,r_,,)

echo "CFLAGS = $CFLAGS"
echo "LIBS = `pkg-config --libs ${MOD}`"

valaswig-cc ${LNG} ${MOD} ${VALASWIGFLAGS} \
	-x --vapidir=../vapi ../vapi/${MOD} \
	`pkg-config --cflags --libs ${MOD}`
