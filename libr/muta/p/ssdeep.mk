OBJ_SSDEEP=muta_ssdeep.o

R2DEPS+=r_util
DEPFLAGS=-L../../util -lr_util -L.. -lr_codec

STATIC_OBJ+=${OBJ_SSDEEP}
TARGET_SSDEEP=muta_ssdeep.${EXT_SO}

ALL_TARGETS+=${TARGET_SSDEEP}

${TARGET_SSDEEP}: ${OBJ_SSDEEP}
	${CC} $(call libname,muta_ssdeep) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_SSDEEP} ${OBJ_SSDEEP} $(DEPFLAGS)
