OBJ_MDT=bin_mdt.o
OBJ_MDT+=../format/mdt/mdt.o

STATIC_OBJ+=${OBJ_MDT}
TARGET_MDT=bin_mdt.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_MDT}

${TARGET_MDT}: ${OBJ_MDT}
	-${CC} $(call libname,bin_mdt) ${CFLAGS} ${OBJ_MDT} $(LINK) $(LDFLAGS)
endif