CC				= gcc
LIBNAME		= libgdbr
MAJOR			= 0
MINOR			= 1
CFLAGS		= -Wall -g -O0 -ggdb # -std=gnu11
LD				= gcc
LDFLAGS		= -L /usr/lib	-L /usr/local/lib

# Test variables
TEST_D		= $(PWD)/test
BIN				= $(PWD)/bin
UNIT_TEST = $(TEST_D)/unit.c
CLIENT		= $(TEST_D)/client.c

PWD				= .
TEST			= $(PWD)/test
LIB				= $(PWD)/lib
INCLUDES 	= -I $(PWD)/include

TEST_INCLUDES += $(INCLUDES) -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include

SRC_D			= $(PWD)/src
SRC_C			= $(wildcard $(SRC_D)/*.c)
SRC_O			= $(SRC_C:.c=.o)

TEST_C		= $(wildcard $(TEST_D)/*.c)
TEST_O		= $(TEST_C:.c=.o)


$(SRC_O): %.o : %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -fPIC $< -o $@

all: make
default: make

prepare:
	mkdir -p $(LIB)

lib: prepare $(SRC_O)
	$(LD) -shared -Wl,-soname,$(LIBNAME).so -o $(LIB)/$(LIBNAME).so $(SRC_O)
	ar rvs $(LIB)/$(LIBNAME).a $(SRC_O)

clean:
	-rm $(SRC_O)
	-rm $(LIB)/*

unit: lib 
	$(CC) $(CFLAGS) $(TEST_INCLUDES) -c $(UNIT_TEST) -o $(TEST_D)/unit.o
	$(LD) $(TEST_D)/unit.o -o $(TEST_D)/unit -L$(LIB) -lgdbr -lglib-2.0

run_unit: unit
	LD_LIBRARY_PATH=./lib ./test/unit

client: lib
	$(CC) $(CFLAGS) $(INCLUDES) -c $(CLIENT) -o $(TEST_D)/client.o
	$(LD) $(TEST_D)/client.o -o $(TEST_D)/client -L$(LIB) -lgdbr

run_test: client
	LD_LIBRARY_PATH=./lib ./test/client

gdb_test: client
	LD_LIBRARY_PATH=./lib gdb ./test/client

valgrind_test: client
	LD_LIBRARY_PATH=./lib valgrind --track-origins=yes -v --leak-check=full ./test/client

edit:
	vim -c "args **/*.h **/*.c"
