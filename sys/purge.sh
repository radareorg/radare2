#!/bin/sh

if [ -z "${MAKE}" ]; then
	 MAKE=make
	gmake --help >/dev/null 2>&1
	[ $? = 0 ] && MAKE=gmake
fi

# TODO: Query the user before taking any action
read -p "All files related to current and previous installations of r2 
(including libraries) will be deleted. Continue?[y/n] " -n 1 -r
if [[ $REPLY =~ ^[Yy]$ ]]
then
    if [ -x /usr/bin/apt-get ] ; then
	    sudo apt-get remove radare2
	    sudo apt-get remove libradare2-common
	    sudo apt-get remove --auto-remove libradare2-common
	    sudo apt-get purge libradare2-common
	    sudo apt-get purge --auto-remove libradare2-common
	    sudo apt-get remove libradare2
	    sudo apt-get remove --auto-remove libradare2
	    sudo apt-get purge libradare2
	    sudo apt-get purge --auto-remove libradare2
    fi
    # TODO: support brew
    # TODO: support archlinux
    # TODO: support gentoo
    exit 0
else
    echo -n "Aborting."
    exit 1
fi


