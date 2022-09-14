OBJ_WII_REL=bin_rel.o

STATIC_OBJ+=${OBJ_WII_REL}
TARGET_WII_REL=bin_rel.${EXT_SO}

ALL_TARGETS+=${TARGET_WII_REL}

${TARGET_WII_REL}: ${OBJ_WII_REL}
ifeq ($(CC),cccl)
	${CC} $(call libname,bin_rel) ${CFLAGS} $(OBJ_WII_REL) $(LINK) $(LDFLAGS) \
	-L../../magic -llibr_magic
else
	${CC} $(call libname,bin_rel) ${CFLAGS} $(OBJ_WII_REL) $(LINK) $(LDFLAGS) \
	-L../../magic -lr_magic
endif
