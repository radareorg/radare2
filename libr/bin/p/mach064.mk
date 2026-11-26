OBJ_MACH064=bin_mach064.o
OBJ_MACH064+=bin_write_mach064.o
OBJ_MACH064+=../format/mach0/mach064.o

STATIC_OBJ+=${OBJ_MACH064}
TARGET_MACH064=bin_mach064.${EXT_SO}

ALL_TARGETS+=${TARGET_MACH064}

ifeq ($(CC),cccl)
${TARGET_MACH064}: LDFLAGS+=-L$(LTOP)/muta -llibr_muta
else
${TARGET_MACH064}: LDFLAGS+=-L$(LTOP)/muta -lr_muta
endif

${TARGET_MACH064}: ${OBJ_MACH064}
	-${CC} $(call libname,bin_mach064) \
		-shared ${CFLAGS} -o ${TARGET_MACH064} \
		${OBJ_MACH064} $(LINK) $(LDFLAGS)
