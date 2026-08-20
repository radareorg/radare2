OBJ_PTX=p/ptx/plugin.o

STATIC_OBJ+=$(OBJ_PTX)
TARGET_PTX=p/arch_ptx.$(EXT_SO)

ALL_TARGETS+=$(TARGET_PTX)

$(TARGET_PTX): $(OBJ_PTX)
	${CC} $(call libname,arch_ptx) ${LDFLAGS} ${CFLAGS} -o $(TARGET_PTX) $(OBJ_PTX)
