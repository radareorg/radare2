OBJ_DOLPHIN=bin_dol.o

STATIC_OBJ+=${OBJ_DOLPHIN}
TARGET_DOLPHIN=bin_dol.${EXT_SO}

ALL_TARGETS+=${TARGET_DOLPHIN}

${TARGET_DOLPHIN}: ${OBJ_DOLPHIN}
	${CC} $(call libname,bin_dol) ${CFLAGS} $(OBJ_DOLPHIN) $(LINK) $(LDFLAGS) \
	-L../../magic -lr_magic
