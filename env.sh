#!/bin/sh

pfx=$1
if [ -z "$pfx" ]; then
	echo "Usage: ./env.sh [path-to-prefix]"
	exit 1
fi

new_env='
LIBR_PLUGINS=${pfx}/lib/radare2
PATH=$pfx/bin:${PATH}
LD_LIBRARY_PATH=$pfx/lib:$LD_LIBRARY_PATH
DYLD_LIBRARY_PATH=$pfx/lib:$LD_LIBRARY_PATH
PKG_CONFIG_PATH=$PWD/libr/
'

echo
echo "==> Entering radare2 environment shell..."
echo
echo $new_env $SHELL \
   | sed -e 's, ,\n,g' \
   | sed -e 's,^,  ,g' \
   | sed -e 's,$, \\,'
echo

eval $new_env $SHELL

echo
echo "==> Back to system shell..."
echo
