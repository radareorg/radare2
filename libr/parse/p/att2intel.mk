OBJ_ATTINTEL+=parse_att2intel.o

TARGET_ATTINTEL=parse_att2intel.${EXT_SO}
STATIC_OBJ+=${OBJ_ATTINTEL}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_ATTINTEL}
${TARGET_ATTINTEL}: ${OBJ_ATTINTEL}
	${CC} $(call libname,parse_att2intel) ${LINK} \
		-L.. -L../../util -lr_util $(LDFLAGS_SHARED) \
		${CFLAGS} -o ${TARGET_ATTINTEL} ${OBJ_ATTINTEL}
endif
