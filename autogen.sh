#!/bin/sh
#
# Look for the 'acr' tool here: https://github.com/radare/acr
# Clone last version of ACR from here:
#  git clone https://github.com/radare/acr
#
# -- pancake

[ -z "$EDITOR" ] && EDITOR=vim
$EDITOR configure.acr

r2pm -h >/dev/null 2>&1
if [ $? = 0 ]; then
	echo "Installing the last version of 'acr'..."
	r2pm -i acr > /dev/null
	r2pm -r acr -h > /dev/null 2>&1
	if [ $? = 0 ]; then
		echo "Running 'acr -p'..."
		r2pm -r acr -p || exit 1
	else
		echo "Cannot find 'acr' in PATH"
	fi
else
	echo "Running acr..."
	acr -p || exit 1

fi
if [ -d subprojects ]; then
	cd subprojects || exit 1
	sh autogen.sh
	cd ..
fi
V=`./configure -qV | cut -d - -f -1`
meson rewrite kwargs set project / version "$V"
if [ -n "$1" ]; then
	echo "./configure $*"
	./configure $*
fi

setver() {
	F=$1
	shift
	sed "$@" < "$F" > "$F.tmp" && cat "$F.tmp" > "$F"
	rm -f "$F.tmp"
}
setver sys/install-debs.sh -e 's,^\[ -z "$V" \] && V=".*",[ -z "$V" ] \&\& V="'$V'",'
setver dist/rpm/radare2.spec -e 's,^\(Version:[[:space:]]*\).*,\1'$V','
setver dist/npm/package.json -e 's,^\(  "version": "\)[^"]*",\1'$V'",'
setver dist/nix/package.nix -e 's,^\(  version = "\)[^"]*",\1'$V'",'
for a in dist/wapm/*/wapm.toml ; do
	setver $a -e 's,^version = ".*",version = "'$V'",'
done
$EDITOR README.md
