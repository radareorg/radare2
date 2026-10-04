CORE_OBJ_PANELS=panels/plugin.o

STATIC_OBJ+=${CORE_OBJ_PANELS}
CORE_TARGET_PANELS=core_panels.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${CORE_TARGET_PANELS}

panels/plugin.shared.o: panels/plugin.c panels/panels.h panels/free.h ../visual_modes.h $(wildcard panels/*.inc.c)
	${CC} $(filter-out %.a,${CFLAGS}) -UR2_PLUGIN_INCORE -c -o $@ panels/plugin.c

${CORE_TARGET_PANELS}: panels/plugin.shared.o
	${CC} $(call libname,core_panels) panels/plugin.shared.o \
		-o ${CORE_TARGET_PANELS} ${CFLAGS}
endif
