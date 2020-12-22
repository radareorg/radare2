# Ugly yet that's the path inside dockcross
ifeq (${PATH},"/usr/arm-linux-androideabi/bin/${ARCH}-linux-androideabi-gcc")
CC=${ARCH}-linux-androideabi-gcc
USERCC=${ARCH}-linux-androideabi-gcc -fPIC -fPIE
else
CC=ndk-gcc -fPIC -fPIE
USERCC=ndk-gcc -fPIC -fPIE
endif

ARCH=arm

ifeq (${NDK_ARCH},x86)
# mips
ARCH2=i686
CROSS=${ARCH2}-linux-android-
endif

ifeq (${NDK_ARCH},mips)
# mips
ARCH2=mipsel
CROSS=${ARCH2}-linux-android-
endif

ifeq (${NDK_ARCH},mips64)
# mips
ARCH2=mips64el
CROSS=${ARCH2}-linux-android-
endif

ifeq (${NDK_ARCH},arm)
# arm32
ARCH=arm
CROSS=${ARCH}-linux-androideabi-
endif

ifeq (${NDK_ARCH},aarch64)
# aarch64
ARCH=aarch64
CROSS=${ARCH}-linux-android-
endif

ifeq (${NDK_ARCH},)
all::
	echo "Undefined NDK_ARCH"
	exit 1
endif

RANLIB=${CROSS}ranlib
AR=${CROSS}ar
CC_AR=${CROSS}ar -r ${LIBAR}
PARTIALLD=${CROSS}ld -r
# -all_load
ONELIB=0
OSTYPE=android
#LINK=
#CC_AR=ndk-ar -r ${LIBAR}
PICFLAGS=-fPIC -fpic
LDFLAGS_LIB=-shared
CFLAGS+=${PICFLAGS}
CC_LIB=${CC} -shared -o
CFLAGS_INCLUDE=-I
LDFLAGS_LINK=-l
LDFLAGS_LINKPATH=-L
CFLAGS_OPT0=-O0
CFLAGS_OPT1=-O1
CFLAGS_OPT2=-O2
CFLAGS_OPT3=-O3
CFLAGS_DEBUG=-g
OBJCOPY=${CROSS}objcopy
