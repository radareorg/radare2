OBJ_M68XX_CS=anal_m68xx_cs.o

include ${CURDIR}capstone.mk

STATIC_OBJ+=$(OBJ_M68XX_CS)

TARGET_M68XX_CS=anal_m68xx_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_M68XX_CS}

${TARGET_M68XX_CS}: ${OBJ_M68XX_CS}
	${CC} ${CFLAGS} $(call libname,anal_m68xx_cs) $(CS_CFLAGS) \
		-o anal_m68xx_cs.${EXT_SO} ${OBJ_M68XX_CS} $(CS_LDFLAGS)
