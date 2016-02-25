#!/bin/sh

getabsolutepath() {
	[ -d "$1" ] && { cd "$1"; echo "$(pwd -P)"; } ||
	{ cd "$(dirname "$1")"; echo "$(pwd -P)/$(basename "$1")"; }
}

pfx=$(getabsolutepath "$1")

if [ -z "$1" ]; then
	echo "Usage: ./env.sh [destdir|prefix] [program]"
	exit 1
fi

if [ ! -d "$pfx" ]; then
	echo "Cannot find $pfx directory"
	exit 1
fi

# Support DESTDIR
if [ -d "$pfx/usr/bin" ]; then
	pfx="$pfx/usr"
fi

new_env='
LIBR_PLUGINS=${pfx}/lib/radare2
PATH=$pfx/bin:${PATH}
LD_LIBRARY_PATH=$pfx/lib:$LD_LIBRARY_PATH
DYLD_LIBRARY_PATH=$pfx/lib:$DYLD_LIBRARY_PATH
PKG_CONFIG_PATH=$pfx/lib/pkgconfig:$PKG_CONFIG_PATH
'

shift

if [ -z "$*" ]; then
	echo
	echo "==> Entering radare2 environment shell..."
	echo
	echo $new_env $* \
	   | sed -e 's, ,\n,g' \
	   | sed -e 's,^,  ,g' \
	   | sed -e 's,$, \\,'
	echo
	export PS1="r2env.sh$ "
	eval $new_env $SHELL
	echo
	echo "==> Back to system shell..."
	echo
else
	if [ "$#" -gt 1 ]; then
		par=""
		p=0
		while : ; do
			p=$(($p+1))
			[ $p -gt $# ] && break
			a=`eval echo "\$\{$p\}"`
			par="$par\"$a\" "
		done
		eval $new_env $par
	else
		eval $new_env $*
	fi
fi
