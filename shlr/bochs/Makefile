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
#CFLAGS=-Wall -g -O0 -ggdb # -std=gnu11
LD=$(CC)
LDFLAGS+=-L${LIBR}/socket -lr_socket
LDFLAGS+=-L${LIBR}/util -lr_util
ifeq ($(OSTYPE),darwin)
LDFLAGS_SHARED=-dynamiclib
else
LDFLAGS_SHARED=-shared
endif
#OSTYPE=windows
include ../../libr/socket/deps.mk

SRC_D=src
SRC_C=$(wildcard $(SRC_D)/*.c)
SRC_O=$(SRC_C:.c=.o)

all: $(LIB)/$(LIBNAME).a

#$(LD) -shared -Wl,-soname,$(LIBNAME).so -o $(LIB)/$(LIBNAME).so $(SRC_O)
$(LIB):
	mkdir -p $(LIB)

$(LIB)/$(LIBNAME).a: $(LIB) $(SRC_O)
	mkdir -p $(LIB)
	$(LD) $(PIC_CFLAGS) $(LDFLAGS_SHARED) -o $(LIB)/$(LIBFILE) $(CFLAGS) $(SRC_O) $(LDFLAGS) $(LINK)
	$(AR) rvs $(LIB)/$(LIBNAME).a $(SRC_O)
	$(RANLIB) $(LIB)/$(LIBNAME).a

clean:
	-rm -f $(SRC_O)
	-rm -rf lib
