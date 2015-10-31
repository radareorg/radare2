OBJ_MDMP=bin_mdmp.o
OBJ_MDMP+=../format/mdmp/mdmp.o

STATIC_OBJ+=${OBJ_MDMP}
TARGET_MDMP=bin_mdmp.${EXT_SO}

ALL_TARGETS+=${TARGET_MDMP}
LDFLAGS+=-L../../db -lr_db

${TARGET_MDMP}: ${OBJ_MDMP}
	${CC} $(call libname,bin_mdmp) ${CFLAGS} $(LDFLAGS) ${OBJ_MDMP}
