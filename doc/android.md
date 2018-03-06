r2 on android
=============

Install NDK in archlinux x86-64
 - Enable multilib repo in pacman.conf
 - pacman -S lib32-glibc lib32-zlib

To build r2 for android you need to install the NDK:

    http://developer.android.com/tools/sdk/ndk/index.html

Edit `~/.r2androidrc` to setup the paths to your ndk

    sys/android-shell.sh
    ./configure --with-compiler=android --with-ostype=android --prefix=/data/radare2 --without-pic --with-nonpic
    make -j 4

To compile for android-x86

    export NDK_ARCH=x86

To package:

    mkdir 
    make install DESTDIR=/usr

Build farm, see `sys/android-shell.sh` and `sys/android-build.sh`
    
    sys/android-shell.sh sys/android-build.sh arm-static

Environment:

    NDK_ARCH=arm|x86
    STATIC_BUILD=0|1
