OBJ_PDP11=p/pdp11/plugin.o
OBJ_PDP11+=p/pdp11/pdp11-dis.o
OBJ_PDP11+=p/pdp11/pdp11-opc.o

TARGET_PDP11=arch_pdp11_gnu.${EXT_SO}
STATIC_OBJ+=${OBJ_PDP11}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_PDP11}
${TARGET_PDP11}: ${OBJ_PDP11}
	${CC} $(call libname,arch_pdp11) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_PDP11} ${OBJ_PDP11}
endif
