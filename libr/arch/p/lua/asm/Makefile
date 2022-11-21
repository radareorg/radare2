EXT_SO=$(shell r2 -H LIBEXT)
WITHPIC=1
CFLAGS+=$(shell pkg-config --cflags --libs r_asm)
LDFLAGS+=-shared -fPIC

include lua53.mk

all: $(TARGET_LUA53)
