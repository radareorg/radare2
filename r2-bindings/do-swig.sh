#!/bin/sh
# Copyleft 2011-2012
# Author: pancake(at)nopcode.org
# Wrapper for valabind-cc

LNG=$1
MOD=$2
VALABINDFLAGS="" ; [ 1 = "${DIST}" ] && VALABINDFLAGS="-C"
if [ -z "${MOD}" ]; then
	echo "Usage: ./libr-swig.sh [python] [r_foo]"
	exit 1
fi
mkdir -p ${LNG}
cd ${LNG}

#valabind-cc ${LNG} ${MOD} -I../../libr/include ../../libr/vapi/${MOD}.vapi -l${MOD} -L../../libr/$(echo ${MOD} | sed -e s,r_,,)

echo "Build ${MOD} `pkg-config --libs ${MOD}`"

case "${LNG}" in
*node*)
	VBMODE=''
	;;
*)
	VBMODE=--swig
	;;
esac

PYTHON_CONFIG=$(../python-config-wrapper -n)
export PYTHON_CONFIG
echo valabind-cc ${LNG} ${MOD} ${VALABINDFLAGS} \
	-NRadare ${VBMODE} \
	-I../../libr/include \
	-x --vapidir=../vapi ../vapi/${MOD} \
	`pkg-config --cflags --libs ${MOD}`
exec valabind-cc ${LNG} ${MOD} ${VALABINDFLAGS} \
	-NRadare ${VBMODE} \
	-I../../libr/include \
	-x --vapidir=../vapi ../vapi/${MOD} \
	`pkg-config --cflags --libs ${MOD}`
