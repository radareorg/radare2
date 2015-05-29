OBJ_OMF=bin_omf.o \
	../format/omf/omf.o

STATIC_OBJ+=${OBJ_OMF}
TARGET_OMF=bin_omf.${EXT_SO}

ALL_TARGETS+=${TARGET_OMF}

${TARGET_OMF}: ${OBJ_OMF}
	${CC} $(call libname,bin_omf) ${CFLAGS} \
		$(OBJ_OMF) $(LINK) $(LDFLAGS)
