#!/bin/sh

if [ -z "${MAKE}" ]; then
	 MAKE=make
	gmake --help >/dev/null 2>&1
	[ $? = 0 ] && MAKE=gmake
fi

echo "All files related to current and previous installations 
of r2 (including libraries) will be deleted. Continue? (y/n) "
read answer
case "$answer" in
y|Y)
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
esac

echo "Aborting."
exit 1
