#!/bin/sh
#
# Look for the 'acr' tool here: http://www.nopcode.org/
# Clone last version of ACR from here:
#  hg clone http://youterm.com/hg/acr
#
# -- pancake
acr -p
if [ -n "$1" ]; then
	echo "./configure $@"
	./configure $@
fi
