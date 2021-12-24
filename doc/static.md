Statically Linking r2
=====================

Before you try to statically link r2, you should know about the licenses that go along with it, see doc/license for more information.

Instructions
------------

In order to create a static library, configure with:

	./configure --prefix=/usr --with-nonpic --without-pic

or just run

	sys/static.sh

Android
-------

Bear in mind that the Android build is done statically to simplify distribution and speedup loading times (no need to dynamically resolve external symbols or load libraries). You can achieve this running the following script (for example):

	sys/android-arm.sh

The build environment for the NDK can be setup by using the:

	sys/android-shell.sh arm
