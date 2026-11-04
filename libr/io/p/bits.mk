OBJ_BITS=io_bits.o

STATIC_OBJ+=$(OBJ_BITS)
TARGET_BITS=io_bits.$(EXT_SO)
ALL_TARGETS+=$(TARGET_BITS)

ifeq ($(WITHPIC),0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

$(TARGET_BITS): ${OBJ_BITS}
	$(CC_LIB) $(call libname,io_bits) ${CFLAGS} -o ${TARGET_BITS} \
		$(LDFLAGS) ${OBJ_BITS} ${LINKFLAGS}
