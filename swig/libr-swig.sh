#!/bin/sh
MOD=$1
if [ -z "${MOD}" ]; then
	echo "Usage: ./libr-swig.sh [r_foo]"
	exit 1
fi
valaswig-cc python ${MOD} -I../libr/include ../libr/vapi/${MOD}.vapi -l${MOD}
