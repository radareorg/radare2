OBJ_SFS=fs_sfs.o
EXTRA=$(GRUB)
CFLAGS+=-Igrub/include

STATIC_OBJ+=${OBJ_SFS}
#STATIC_OBJ+=${EXTRA}
TARGET_SFS=fs_sfs.${EXT_SO}

ALL_TARGETS+=${TARGET_SFS}

${TARGET_SFS}: ${OBJ_SFS}
	${CC} $(call libname,fs_sfs) ${LDFLAGS} ${CFLAGS} -o ${TARGET_SFS} ${OBJ_SFS} ${EXTRA}
