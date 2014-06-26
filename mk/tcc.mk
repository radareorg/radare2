CC=tcc
RANLIB=ranlib
LINK=
ONELIB=0
CC_AR=ar -r ${LIBAR}
CC_LIB=${CC} -shared -o ${LIBSO}
CFLAGS_INCLUDE=-I
LDFLAGS_LINK=-l
LDFLAGS_LINKPATH=-L
CFLAGS_OPT0=-O0
CFLAGS_OPT1=-O1
CFLAGS_OPT2=-O2
CFLAGS_OPT3=-O3

ifeq ($(OSTYPE),auto)
OSTYPE=$(shell uname | tr 'A-Z' 'a-z')
endif
ifneq (,$(findstring cygwin,$(OSTYPE)))
PIC_CFLAGS=
else
ifneq (,$(findstring mingw32,${OSTYPE}))
PIC_CFLAGS=
else
PIC_CFLAGS=-fPIC
endif
endif
ifeq ($(OSTYPE),darwin)
LDFLAGS_LIB=-dynamiclib
LDFLAGS_SONAME=-Wl,-install_name,
else
LDFLAGS_LIB=-shared
LDFLAGS_LIB+=-Dxx
#Wl,-soname,lib${NAME}.${EXT_SO}.${VERSION}
LDFLAGS_SONAME=-Dxx
#Wl,-soname=
endif

CC_LIB=${CC} ${LDFLAGS_LIB} -o ${LIBSO}
FLAGS_DEBUG=-g
