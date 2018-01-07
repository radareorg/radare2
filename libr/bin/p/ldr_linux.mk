OBJ_LDR_LINUX=bin_ldr_linux.o

STATIC_OBJ+=${OBJ_LDR_LINUX}
TARGET_LDR_LINUX=bin_ldr_linux.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_LDR_LINUX}

${TARGET_LDR_LINUX}: ${OBJ_LDR_LINUX}
	-${CC} $(call libname,bin_ldr_linux) -shared ${CFLAGS} \
	-o ${TARGET_LDR_LINUX} ${OBJ_LDR_LINUX} $(LINK) $(LDFLAGS)
endif
