CC=tcc -D__LITTLE_ENDIAN__=1
RANLIB?=ranlib
ONELIB=0
AR?=ar
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
PARTIALLD=${LD} -r -all_load
LDFLAGS_LIB=-dynamiclib
LDFLAGS_SONAME=-soname
# LDFLAGS_SONAME=-Wl,-install_name,
else
PARTIALLD=${LD} -r --whole-archive
LDFLAGS_LIB=-shared
LDFLAGS_LIB+=-Dxx
#Wl,-soname,lib${NAME}.${EXT_SO}.${VERSION}
LDFLAGS_SONAME=-soname
#Wl,-soname=
endif

CC_LIB=${CC} ${LDFLAGS_LIB} -o ${LIBSO}
FLAGS_DEBUG=-g
