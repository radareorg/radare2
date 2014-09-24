include ../../libr/config.mk
EDITOR?=vim
CC?=gcc
AR?=ar
RANLIB?=ranlib
LIBNAME=libgdbr
LIBFILE=$(LIBNAME).$(EXT_SO)
CFLAGS+=-I$(LIBR)/include -fPIC
CFLAGS+=-Iinclude -I${LIBR}/include
MAJOR=0
MINOR=1
#CFLAGS=-Wall -g -O0 -ggdb # -std=gnu11
LD=$(CC)
LDFLAGS=-L ${LIBR}/socket -lr_socket
#OSTYPE=windows
include ../../libr/socket/deps.mk

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
SRC_C=$(wildcard $(SRC_D)/*.c)
SRC_O=$(SRC_C:.c=.o)

TEST_C=$(wildcard $(TEST_D)/*.c)
TEST_O=$(TEST_C:.c=.o)

all: $(LIB)/$(LIBNAME).a
#	make

default: make

prepare:
	mkdir -p $(LIB)

#$(LD) -shared -Wl,-soname,$(LIBNAME).so -o $(LIB)/$(LIBNAME).so $(SRC_O)
$(LIB):
	mkdir -p $(LIB)

$(LIB)/$(LIBNAME).a: $(LIB) $(SRC_O)
	$(LD) -shared -o $(LIB)/$(LIBFILE) $(SRC_O) $(LDFLAGS)
	$(AR) rvs $(LIB)/$(LIBNAME).a $(SRC_O)
	# required for solaris and w32
	$(RANLIB) $(LIB)/$(LIBNAME).a

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
