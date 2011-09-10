#!/bin/sh

if [ -x /usr/bin/pacman ]; then
	sudo pacman -S mingw32-gcc
elif [ -x /usr/bin/apt-get ]; then
	sudo apt-get install mingw32
elif [ -x /opt/local/bin/port ]; then
	sudo port install i386-mingw32-gcc 
else
	echo "ubuntu/debian or archlinux required."
	exit 1
fi
