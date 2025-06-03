OBJ_SERPENT=muta_serpent.o p/algo/serpent.o

R2DEPS+=r_util
# DEPFLAGS=-L../../util -lr_util -L.. -lr_codec

STATIC_OBJ+=${OBJ_SERPENT}
TARGET_SERPENT=muta_serpent.${EXT_SO}

ALL_TARGETS+=${TARGET_SERPENT}

${TARGET_SERPENT}: ${OBJ_SERPENT}
	${CC} $(call libname,muta_serpent) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_SERPENT} ${OBJ_SERPENT} $(DEPFLAGS)
