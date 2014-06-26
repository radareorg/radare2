ifeq (${_INCLUDE_MK_GCC_},)
_INCLUDE_MK_GCC_=1
CC?=gcc
LINK=
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

ifeq ($(OSTYPE),auto)
OSTYPE=$(shell uname | tr 'A-Z' 'a-z')
endif
ifneq (,$(findstring cygwin,${OSTYPE}))
PIC_CFLAGS=
else
ifneq (,$(findstring mingw32,${OSTYPE}))
PIC_CFLAGS=
else
PIC_CFLAGS=-fPIC
endif
endif
ifeq ($(OSTYPE),darwin)
ARCH=$(shell uname -m)
#CFLAGS+=-arch ${ARCH}
#LDFLAGS+=-arch ${ARCH}
LDFLAGS_LIB=-dynamiclib
LDFLAGS_SONAME=-Wl,-install_name,${LIBDIR}/
else
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
