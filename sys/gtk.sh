#!/bin/sh

if [ -x /usr/bin/pacman ]; then
	sudo pacman -S gtk2
elif [ -x /usr/bin/apt-get ]; then
	sudo apt-get install gtk2-2.0-dev
elif [ -x /opt/local/bin/port ]; then
	echo "Installing cairo.."
	sudo port install cairo +quartz+no_x11 || exit 1
	echo "Installing pango.."
	sudo port install pango +quartz+no_x11 || exit 1
	echo "Installing GTK2.."
	sudo port install gtk2 +quartz+no_x11 || exit 1
else
	echo "Cannot install gtk :("
	exit 1
fi
:> .gtk-done.sh
