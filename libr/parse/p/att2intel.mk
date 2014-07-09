OBJ_ATTINTEL+=parse_att2intel.o

TARGET_ATTINTEL=parse_att2intel.${EXT_SO}
ALL_TARGETS+=${TARGET_ATTINTEL}
STATIC_OBJ+=${OBJ_ATTINTEL}

${TARGET_ATTINTEL}: ${OBJ_ATTINTEL}
	${CC} $(call libname,parse_att2intel) ${LINK} \
		-L.. -L../../util -lr_util -shared \
		${CFLAGS} -o ${TARGET_ATTINTEL} ${OBJ_ATTINTEL}
