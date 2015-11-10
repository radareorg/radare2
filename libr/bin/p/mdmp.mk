OBJ_MDMP=bin_mdmp.o
OBJ_MDMP+=../format/mdmp/mdmp.o

STATIC_OBJ+=${OBJ_MDMP}
TARGET_MDMP=bin_mdmp.${EXT_SO}

LINK+=-L../../db -lr_db $(SHLR)/sdb/src/libsdb.a
ifeq (${WITHPIC},1)
ALL_TARGETS+=${TARGET_MDMP}

${TARGET_MDMP}: ${OBJ_MDMP}
	${CC} $(call libname,bin_mdmp) $(LINK) \
	${CFLAGS} $(LDFLAGS) ${OBJ_MDMP}
endif
