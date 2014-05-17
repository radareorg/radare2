Crosscompiling from OSX:
========================

export PATH=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin:$PATH
export CC=`pwd`/sys/ios-sdk-gcc
# set only for arm64, otherwise it is armv7
export CPU=arm64
# select ios sdk version
export IOSVER=7.1
./configure --prefix=/usr --with-ostype=darwin --with-compiler=ios-sdk --target=arm-unknown-darwin
make -j4
make install DESTDIR=/tmp/r2ios


Natively compiling on iOS
=========================

SSH into your iDevice and run the following steps:

Setup SDK for ARMv6
-------------------
1) Install 'APT 0.7 Strict' and OpenSSH packages from cydia.

	apt-get coreutils install wget inetutils rsync git expat curl

2) Download missing packages from lolcathost:

	wget http://lolcathost.org/b/libgcc_4.2-20080410-1-6_iphoneos-arm.deb
	wget http://lolcathost.org/b/libSystem.dylib

3) Install them

	dpkg -i libgcc_4.2-20080410-1-6_iphoneos-arm.deb
	apt-get install com.bigboss.20toolchain
	cp libSystem.dylib /usr/lib
	cd /usr/lib ; ln -sf  libSystem.dylib libm.dylib
	apt-get install make vim gawk git

4) /var/include/sys/stat.h is broken.

	Solution: add 'int foo[3];' after 'st_rdev' at line 178

5) Get the varinclude tarball

	wget lolcathost.org/b/varinclude.tar.gz 
	tar xzvf varinclude.tar.gz -C /

Compilation
-----------
	export CC=gcc
	export CFLAGS=-I/var/include
	export CPPFLAGS=-I/var/include
	./configure --prefix=/usr --with-ostype=darwin
	make
	make symstall

Usage
-----
	export R2DIR=/private/var/radare2
	export PATH=${R2DIR}/bin:$PATH
	export DYLD_LIBRARY_PATH=${R2DIR}/lib
	r2 ...

Building with the ARMv7 SDK
---------------------------
From coolstar repo we get the ios toolchain

	apt-get coreutils install wget inetutils
	apt-get install basename git make expat 
	apt-get install org.coolstar.iostoolchain

* Copy crt1.o and dylib1.o from your iOS SDK into /usr/lib

	/Applications//Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS7.0.sdk/

* Current r2 build requires 'gcc' as native compiler to
  build a standalone 'sdb' to precompile some files. This
  dependency will be probably

	cd /usr/bin
	ln -fs clang gcc
 
Build
-----
	export CC=clang
	export CFLAGS=-I/var/include
	export CPPFLAGS=-I/var/include
	./configure --prefix=/usr --with-ostype=darwin
	make
	make symstall

Packaging
---------
Make a fake install in a temporary directory:

	rm -rf /tmp/r2
	make install DESTDIR=/tmp/r2
	cd /tmp/r2
	tar czvpf ../r2.tgz *

Clone the cydia repo from radare's github

	git clone https://github.com/radare/cydia
	cd cydia/radare2*
	mkdir root
	tar xzvf r2.tgz -C root
	vim CONFIG # bump version
	make

Signing
-------
In order to enable debugger capabilities to the radare2
executable you will need to sign it using the following command:

	cd binr/radare2
	make sign
