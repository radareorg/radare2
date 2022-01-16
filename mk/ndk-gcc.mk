ifeq (${_INCLUDE_MK_GCC_},)
_INCLUDE_MK_GCC_=1
CC?=ndk-gcc
OBJCOPY?=objcopy
RANLIB?=ranlib
ONELIB=0
AR?=ar
CC_AR=${AR} q ${LIBAR}
CFLAGS+=-MD
CFLAGS_INCLUDE=-I
LDFLAGS_LINK=-l
LDFLAGS_LINKPATH=-L
CFLAGS_OPT0=-O0
CFLAGS_OPT1=-O1
CFLAGS_OPT2=-O2
CFLAGS_OPT3=-O3
CFLAGS_DEBUG=-g
LD?=ld

ifeq ($(OSTYPE),darwin)
ARCH=$(shell uname -m)
#CFLAGS+=-arch ${ARCH}
#LDFLAGS+=-arch ${ARCH}
PARTIALLD=${LD} -r -all_load
CFLAGS+=-fno-common
LDFLAGS_LIB=-dynamiclib
LDFLAGS_SONAME=-Wl,-install_name,${LIBDIR}/
else
PARTIALLD=${LD} -r --whole-archive
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
