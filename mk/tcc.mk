CC=tcc
RANLIB=ranlib
ONELIB=0
AR=ar
CC_AR=${AR} -r ${LIBAR}
CC_LIB=${CC} -shared -o ${LIBSO}
CFLAGS_INCLUDE=-I
LDFLAGS_LINK=-l
LDFLAGS_LINKPATH=-L
CFLAGS_OPT0=-O0
CFLAGS_OPT1=-O1
CFLAGS_OPT2=-O2
CFLAGS_OPT3=-O3
LD?=ld

ifeq ($(OSTYPE),darwin)
ARCH=$(shell uname -m)
XCODE_VERSION=$(shell xcodebuild -version|grep Xcode|grep -o "[\.0-9]\+")
XCODE_VERSION_MAJOR = $(word 1, $(subst ., ,$(XCODE_VERSION)))
PARTIALLD=${LD} -r -all_load
ifeq ($(XCODE_VERSION_MAJOR),11)
PARTIALLD+=-arch ${ARCH} -platform_version macos 10.14 10.14
endif
LDFLAGS_LIB=-dynamiclib
LDFLAGS_SONAME=-Wl,-install_name,
else
PARTIALLD=${LD} -r --whole-archive
LDFLAGS_LIB=-shared
LDFLAGS_LIB+=-Dxx
#Wl,-soname,lib${NAME}.${EXT_SO}.${VERSION}
LDFLAGS_SONAME=-Dxx
#Wl,-soname=
endif

CC_LIB=${CC} ${LDFLAGS_LIB} -o ${LIBSO}
FLAGS_DEBUG=-g
