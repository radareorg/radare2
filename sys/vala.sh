#!/bin/sh

[ -z "${PREFIX}" ] && PREFIX=/usr

# find root
cd "$(dirname "$PWD/$0")"
. ./CONFIG

mkdir -p _work
cd _work

ccache --help > /dev/null 2>&1
if [ $? = 0 ]; then
	[ -z "${CC}" ] && CC=gcc
	CC="ccache ${CC}"
	export CC
fi

#valac --help > /dev/null 2>&1
#if [ ! $? = 0 ]; then
	# must install from tarball
	VV=0.13.4
	SV=$(echo ${VV}|cut -d . -f 1,2)
	if [ ! -d vala-${VV} ]; then
		wget "http://download.gnome.org/sources/vala/${SV}/vala-${VV}.tar.bz2"
		tar xjvf vala-${VV}.tar.bz2
	fi
	cd vala-${VV} || exit 1
	./configure --prefix="${PREFIX}" || exit 1
	make || exit 1
	sudo make install || exit 1
	cd ..
#fi

exit 0

# git install

if [ -d vala ]; then
	cd vala
	#sudo make uninstall
	git pull
else
	git clone git://git.gnome.org/vala
	cd vala
fi
sh autogen.sh --prefix="${PREFIX}" && \
make -j 4 && \
sudo make install
cd ..
