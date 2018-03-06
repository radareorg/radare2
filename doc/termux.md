Termux
======

Termux is a terminal emulator that ships a base linux environment using the Debian package system
but compiling everything to run on native Android. The result is a fully functional shell on
Android devices for x86, arm and arm64.

Installation
------------

The Termux maintainer of the radare2 package updates the package really fast after every release
which happens every 6 weeks. So in this case, as long as it's supposed to run on embedded devices
it is ok to just install the package from Termux unless you really want to track git master or
develop for this platform.

	sudo apt install radare2

Building from git
-----------------

The packages required to build are:

	sudo apt install git make patch clang

Now you can clone the repo and build:

	git clone --depth 1 https://github.com/radare/radare2
	cd radare2
	sys/termux.sh

Building with meson
-------------------

If you want to build with meson:

	sudo apt install python
	sudo pip install meson
	sudo r2pm -i ninja

And then you can run the build:

	make meson

To install:

	make meson-symstall PREFIX=/data/data/com.termux/files/usr

Updating
--------

To update the repo and rebuild you can do a full and clean rebuild by just running sys/termux.sh
or opt for typing `make` or `make meson` and it will just build what has changed, is something
fails please do a clean build like this:

	git reset --hard
	git clean -xdf
	sys/termux.sh

