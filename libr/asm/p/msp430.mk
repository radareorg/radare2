OBJ_MSP430PSEUDO+=$(LIBR)/arch/p/msp430/pseudo.o

TARGET_MSP430PSEUDO=parse_msp430_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_MSP430PSEUDO}
STATIC_OBJ+=${OBJ_MSP430PSEUDO}

${TARGET_MSP430PSEUDO}: ${OBJ_MSP430PSEUDO}
ifeq ($(CC),cccl)
	${CC} $(call libname,parse_msp430_pseudo) -L../../util -llibr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_MSP430PSEUDO} ${OBJ_MSP430PSEUDO}
else
	${CC} $(call libname,parse_msp430_pseudo) -L../../util -lr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_MSP430PSEUDO} ${OBJ_MSP430PSEUDO}
endif
