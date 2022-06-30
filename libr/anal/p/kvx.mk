OBJ_KVX=anal_kvx.o
OBJ_KVX+=../arch/kvx/kvx-dis.o ../arch/kvx/kvx-reg.o
CFLAGS+=-Iarch

STATIC_OBJ+=$(OBJ_KVX)

TARGET_KVX=anal_kvx.$(EXT_SO)
ifeq ($(WITHPIC),1)
ALL_TARGETS+=$(TARGET_KVX)

$(TARGET_KVX): $(OBJ_KVX)
	${CC} $(call libname,anal_kvx) ${LDFLAGS} ${CFLAGS} -o $(TARGET_KVX) $(OBJ_KVX)
endif
