OBJ_SMS=bin_sms.o

STATIC_OBJ+=${OBJ_SMS}
TARGET_SMS=bin_sms.${EXT_SO}

ALL_TARGETS+=${TARGET_SMS}

${TARGET_SMS}: ${OBJ_SMS}
	${CC} $(call libname,bin_sms) -shared ${CFLAGS} \
		-o ${TARGET_SMS} ${OBJ_SMS} $(LINK) $(LDFLAGS)
