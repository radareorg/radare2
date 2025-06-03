OBJ_SIP=muta_sip.o

STATIC_OBJ+=${OBJ_SIP}
TARGET_SIP=muta_sip.${EXT_SO}

ALL_TARGETS+=${TARGET_SIP}

${TARGET_SIP}: ${OBJ_SIP}
	$(CC) $(call libname,muta_sip) ${LDFLAGS} ${CFLAGS} -o ${TARGET_SIP} ${OBJ_SIP}
