OBJ_PDP11=bin_pdp11.o

STATIC_OBJ+=${OBJ_PDP11}
TARGET_PDP11=bin_pdp11.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_PDP11}

${TARGET_PDP11}: ${OBJ_PDP11}
	-${CC} $(call libname,bin_pdp11) ${CFLAGS} ${OBJ_PDP11} $(LINK) $(LDFLAGS)
endif
