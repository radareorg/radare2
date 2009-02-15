#!/bin/sh

new_env='
LIBR_PLUGINS=$PWD/prefix/lib/radare2
PATH=$PATH:$PWD/prefix/bin
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD/prefix/lib
PKG_CONFIG_PATH=$PWD/libr/
'

echo
echo "==> Entering radare2 environment shell..."
echo
echo $new_env $SHELL \
   | sed -e 's, ,\n,g' \
   | sed -e 's,^,  ,g' \
   | sed -e 's,$,\\,'
echo

eval $new_env $SHELL

echo
echo "==> Back to system shell..."
echo
