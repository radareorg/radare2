ifeq (${_INCLUDE_MK_CLANG_},)
_INCLUDE_MK_CLANG_=1
CC?=clang
RANLIB=ranlib
ONELIB=0
CC_AR=ar q ${LIBAR}
CFLAGS+=-MD
CFLAGS_INCLUDE=-I
LDFLAGS_LINK=-l
LDFLAGS_LINKPATH=-L
CFLAGS_OPT0=-O0
CFLAGS_OPT1=-O1
CFLAGS_OPT2=-O2
CFLAGS_OPT3=-O3
CFLAGS_DEBUG=-g

ifeq ($(OSTYPE),darwin)
ARCH=$(shell uname -m)
XCODE_VERSION=$(shell xcodebuild -version|grep Xcode|grep -o "[\.0-9]\+")
XCODE_VERSION_MAJOR = $(word 1, $(subst ., ,$(XCODE_VERSION)))
PARTIALLD=${LD} -r -all_load
ifeq ($(XCODE_VERSION_MAJOR),11)
PARTIALLD+=-arch ${ARCH} -platform_version macos 10.14 10.14
endif
#CFLAGS+=-arch ${ARCH}
#LDFLAGS+=-arch ${ARCH}
LDFLAGS_LIB=-dynamiclib
LDFLAGS_SONAME=-Wl,-install_name,${LIBDIR}/
else
PARTIALLD=ld -r --whole-archive
LDFLAGS_LIB=${LDFLAGS} -shared
#ifneq (${NAME},)
#LDFLAGS_LIB+=-Wl,-soname,lib${NAME}.${EXT_SO}.${VERSION}
#endif
LDFLAGS_SONAME=-Wl,-soname=
endif
# XXX
#LDFLAGS_SONAME=-D_

CC_LIB=${CC} ${LDFLAGS_LIB} -o ${LIBSO}
endif
