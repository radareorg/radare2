#!/bin/sh
#

LNG=$1
MOD=$2
if [ -z "${MOD}" ]; then
	echo "Usage: ./libr-swig.sh [python] [r_foo]"
	exit 1
fi
mkdir -p ${LNG}
cd ${LNG}

#valaswig-cc ${LNG} ${MOD} -I../../libr/include ../../libr/vapi/${MOD}.vapi -l${MOD} -L../../libr/$(echo ${MOD} | sed -e s,r_,,)

echo LIBS = `pkg-config --libs ${MOD}`

valaswig-cc ${LNG} ${MOD} \
	-x --vapidir=../vapi ../vapi/${MOD} \
	`pkg-config --cflags --libs ${MOD}`
