r2 for Haiku
============

To compile for Haiku run configure in this way:

	HOST_CC=gcc-x86 CC=gcc-x86 ./configure --with-ostype=haiku --prefix=/boot/home/Apps/radare2

And then..

	HOST_CC=gcc-x86 make
	make install
	mv /boot/home/Apps/radare2/bin/* /boot/home/Apps/radare2/
	rmdir /boot/home/Apps/radare2/bin/

To install r2-bindings you will need to install r2, valac, valabind and swig
and copy/link libs to radare2/lib


TODO
====

* Add debugging support
