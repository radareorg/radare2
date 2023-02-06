OBJ_KVX=p/kvx/plugin.o
OBJ_KVX+=p/kvx/kvx-dis.o
OBJ_KVX+=p/kvx/kvx-reg.o

STATIC_OBJ+=$(OBJ_KVX)

TARGET_KVX=p/arch_kvx.$(EXT_SO)

$(TARGET_KVX): $(OBJ_KVX)
	${CC} $(call libname,arch_kvx) ${LDFLAGS} ${CFLAGS} -o $(TARGET_KVX) $(OBJ_KVX)
