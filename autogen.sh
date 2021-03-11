#!/bin/sh
#
# Look for the 'acr' tool here: https://github.com/radare/acr
# Clone last version of ACR from here:
#  git clone https://github.com/radare/acr
#
# -- pancake

r2pm -h >/dev/null 2>&1
if [ $? = 0 ]; then
	echo "Installing the last version of 'acr'..."
	r2pm -i acr > /dev/null
	r2pm -r acr -h > /dev/null 2>&1
	if [ $? = 0 ]; then
		echo "Running 'acr -p'..."
		r2pm -r acr -p
	else
		echo "Cannot find 'acr' in PATH"
	fi
else
	echo "Running acr..."
	acr -p
fi
V=`./configure -qV | cut -d - -f -1`
meson rewrite kwargs set project / version "$V"
if [ -n "$1" ]; then
	echo "./configure $*"
	./configure $*
fi
