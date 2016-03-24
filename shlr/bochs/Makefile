include ../../libr/config.mk
include ../../mk/platform.mk
include ../../shlr/zip/deps.mk
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
#OSTYPE=windows
include ../../libr/socket/deps.mk

SRC_D=src
SRC_C=$(wildcard $(SRC_D)/*.c)
SRC_O=$(SRC_C:.c=.o)

all: $(LIB)/$(LIBNAME).a
#	make

default: make

prepare:
	mkdir -p $(LIB)

#$(LD) -shared -Wl,-soname,$(LIBNAME).so -o $(LIB)/$(LIBNAME).so $(SRC_O)
$(LIB):
	mkdir -p $(LIB)

$(LIB)/$(LIBNAME).a: $(LIB) $(SRC_O)
	$(LD) $(PIC_CFLAGS) -shared -o $(LIB)/$(LIBFILE) $(CFLAGS) $(SRC_O) $(LDFLAGS) $(LINK)
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


valgrind_test: client
	rarun2 libpath=./lib system="valgrind --track-origins=yes -v --leak-check=full ./test/client"

edit:
	$(EDITOR) -c "args **/*.h **/*.c"
