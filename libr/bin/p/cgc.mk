OBJ_CGC=bin_cgc.o

STATIC_OBJ+=${OBJ_CGC}
TARGET_CGC=bin_cgc.${EXT_SO}
LINK+=-L../../db -lr_db

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_CGC}

${TARGET_CGC}: ${OBJ_CGC}
	-${CC} $(call libname,bin_cgc) ${CFLAGS} ${OBJ_CGC} $(LINK) $(LDFLAGS)
endif
