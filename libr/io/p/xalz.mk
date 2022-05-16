OBJ_XALZ=io_xalz.o

STATIC_OBJ+=$(OBJ_XALZ)
TARGET_XALZ=io_xalz.$(EXT_SO)
ALL_TARGETS+=$(TARGET_XALZ)

ifeq ($(WITHPIC),0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

$(TARGET_XALZ): ${OBJ_XALZ}
	$(CC_LIB) $(call libname,io_xalz) ${CFLAGS} -o ${TARGET_XALZ} \
		$(LDFLAGS) ${OBJ_XALZ} ${LINKFLAGS}
