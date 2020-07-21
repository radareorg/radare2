include ../../libr/config.mk
include ../../mk/platform.mk
include ../../mk/$(COMPILER).mk
include ../../shlr/zip/deps.mk
EDITOR?=vim
CC?=gcc
CC_AR?=ar
AR?=$(CC_AR)
RANLIB?=ranlib
LIBNAME=libgdbr
LIBFILE=$(LIBNAME).$(EXT_SO)
CFLAGS+=-I$(LIBR)/include $(PIC_CFLAGS)
CFLAGS+=-Iinclude -I${LIBR}/include
MAJOR=0
MINOR=1
LD=$(CC)
ifeq ($(LD),cccl)
LDFLAGS+=-L${LIBR}/socket -llibr_socket
LDFLAGS+=-L${LIBR}/util -llibr_util
EXT_AR?=lib
else
LDFLAGS+=-L${LIBR}/socket -lr_socket
LDFLAGS+=-L${LIBR}/util -lr_util
EXT_AR?=a
endif

ifeq (${OSTYPE},darwin)
LDFLAGS_SHARED=-dynamiclib
else
LDFLAGS_SHARED=-shared
endif

#OSTYPE=windows
include ../../libr/socket/deps.mk
include ../../shlr/sdb.mk

# Test variables
TEST_D= $(PWD)/test
BIN=$(PWD)/bin
UNIT_TEST=$(TEST_D)/unit.c
CLIENT=$(TEST_D)/client.c

PWD=$(shell pwd)
TEST=test
LIB=lib

TEST_INCLUDES += $(INCLUDES) -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include

SRC_D=src
SRC_C=$(wildcard $(SRC_D)/*.c) $(wildcard $(SRC_D)/*/*.c)
SRC_O=$(SRC_C:.c=.o)

TEST_C=$(wildcard $(TEST_D)/*.c)
TEST_O=$(TEST_C:.c=.o)

all: $(LIB)/$(LIBNAME).${EXT_AR}
#	make

default: make

prepare:
	mkdir -p $(LIB)

$(LIB):
	mkdir -p $(LIB)

$(LIB)/$(LIBNAME).${EXT_AR}: $(LIB) $(SRC_O)
ifeq ($(WITHPIC),1)
	$(LD) $(PIC_CFLAGS) $(LDFLAGS_SHARED) -o $(LIB)/$(LIBFILE) $(CFLAGS) $(SRC_O) $(LDFLAGS) $(LINK)
endif
	$(AR) rvs $(LIB)/$(LIBNAME).${EXT_AR} $(SRC_O)
	# required for solaris and w32
	$(RANLIB) $(LIB)/$(LIBNAME).${EXT_AR}

clean:
	-rm -f $(SRC_O)
	-rm -rf lib

unit: lib
	$(CC) $(CFLAGS) $(TEST_INCLUDES) -c $(UNIT_TEST) -o $(TEST_D)/unit.o
	$(LD) $(TEST_D)/unit.o -o $(TEST_D)/unit -L$(LIB) -lgdbr -lglib-2.0

run_unit: unit
	LD_LIBRARY_PATH=./lib ./test/unit

client: lib
	$(CC) $(CFLAGS) $(INCLUDES) -c $(CLIENT) -o $(TEST_D)/client.o
	$(LD) $(TEST_D)/client.o -o $(TEST_D)/client -L$(LIB) -lgdbr

run_test: client
	rarun2 libpath=./lib program=./test/client

gdb_test: client
	rarun2 libpath=./lib system="gdb ./test/client"

valgrind_test: client
	rarun2 libpath=./lib system="valgrind --track-origins=yes -v --leak-check=full ./test/client"

edit:
	$(EDITOR) -c "args **/*.h **/*.c"
