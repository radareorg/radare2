include ../../libr/config.mk
include ../../mk/platform.mk
EDITOR?=vim
CC?=gcc
AR?=ar
RANLIB?=ranlib
LIBNAME=libbochs
LIBFILE=$(LIBNAME).$(EXT_SO)
CFLAGS+=-I$(LIBR)/include $(PIC_CFLAGS)
CFLAGS+=-Iinclude -I${LIBR}/include
MAJOR=0
MINOR=1
LD=$(CC)
ifeq ($(LD),cccl)
LDFLAGS+=-L${LIBR}/socket -llibr_socket
LDFLAGS+=-L${LIBR}/util -llibr_util
else
LDFLAGS+=-L${LIBR}/socket -lr_socket
LDFLAGS+=-L${LIBR}/util -lr_util
endif
ifeq ($(OSTYPE),darwin)
LDFLAGS_SHARED=-dynamiclib
else
LDFLAGS_SHARED=-shared
endif
#OSTYPE=windows
include ../../libr/socket/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/sdb.mk

SRC_D=src
SRC_C=$(wildcard $(SRC_D)/*.c)
SRC_O=$(SRC_C:.c=.o)

all: lib/$(LIBNAME).$(EXT_AR)

#$(LD) -shared -Wl,-soname,$(LIBNAME).so -o lib/$(LIBNAME).so $(SRC_O)
lib:
	mkdir -p lib

lib/$(LIBNAME).$(EXT_AR): lib $(SRC_O)
	mkdir -p lib
ifeq ($(WITHPIC),1)
	$(LD) $(PIC_CFLAGS) $(LDFLAGS_SHARED) -o lib/$(LIBFILE) $(CFLAGS) $(SRC_O) $(LDFLAGS) $(LINK)
endif
	$(AR) rvs lib/$(LIBNAME).$(EXT_AR) $(SRC_O)
	$(RANLIB) lib/$(LIBNAME).$(EXT_AR)

clean:
	-rm -f $(SRC_O)
	-rm -rf lib
