OBJ_BA2=asm_ba2.o
#OBJ_BA2+=../arch/ba2/ba2_disas.o
#OBJ_BA2+=../arch/ba2/ba2_ass.o
CFLAGS+=-I./arch/ba2/

STATIC_OBJ+=${OBJ_BA2}
TARGET_BA2=asm_ba2.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_BA2}

${TARGET_BA2}: ${OBJ_BA2}
	${CC} $(call libname,asm_ba2) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_BA2} ${OBJ_BA2}
endif


#NAME=asm_ba2
#R2_PLUGIN_PATH=$(shell r2 -H R2_USER_PLUGINS)
#LIBEXT=$(shell r2 -H LIBEXT)
#CFLAGS=-g -fPIC $(shell pkg-config --cflags r_anal)
#LDFLAGS=-shared $(shell pkg-config --libs r_anal)
#OBJS=$(NAME).o
#LIB=$(NAME).$(LIBEXT)

#all: $(LIB)

#clean:
#	rm -f $(LIB) $(OBJS)

#$(LIB): $(OBJS)
#	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(LIB)

#install:
#	cp -f asm_ba2.$(SO_EXT) $(R2_PLUGIN_PATH)

#uninstall:
#	rm -f $(R2_PLUGIN_PATH)/asm_ba2.$(SO_EXT)
