CORE_OBJ_MMC=mmc/plugin.o

STATIC_OBJ+=${CORE_OBJ_MMC}
CORE_TARGET_MMC=core_mmc.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${CORE_TARGET_MMC}

mmc/plugin.shared.o: mmc/plugin.c
	${CC} $(filter-out %.a,${CFLAGS}) -UR2_PLUGIN_INCORE -c -o $@ mmc/plugin.c

${CORE_TARGET_MMC}: mmc/plugin.shared.o
	${CC} $(call libname,core_mmc) mmc/plugin.shared.o \
		-o ${CORE_TARGET_MMC} ${CFLAGS}
endif
