#!/bin/sh

# find root
cd `dirname $PWD/$0`

if [ -x /opt/local/bin/port ]; then
	sudo port install i386-mingw32-gcc
elif [ -x /usr/bin/pacman ]; then
	sudo pacman -S swig
elif [ -x /usr/bin/apt-get ]; then
	sudo apt-get install swig
fi
:>.mark_swig
