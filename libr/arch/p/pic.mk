OBJ_PIC=p/pic/plugin.o

STATIC_OBJ+=$(OBJ_PIC)
OBJ_PIC+=p/pic/pic_midrange.o
OBJ_PIC+=p/pic/pic_baseline.o
OBJ_PIC+=p/pic/pic_pic18.o
TARGET_PIC=arch_pic.$(EXT_SO)

ALL_TARTGETS+=$(TARGET_PIC)

$(TARGET_PIC): $(OBJ_PIC)
	$(CC) $(call libname,arch_pic) ${LDFLAGS} ${CFLAGS} -o arch_pic.$(EXT_SO) $(OBJ_PIC)
