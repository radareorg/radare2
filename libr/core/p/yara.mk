CORE_OBJ_YARA=core_yara.o

#CORE_SHARED_YARA=../../shlr/yara/code.o
#CORE_SHARED_YARA+=../../shlr/yara/class.o
#CORE_SHARED_YARA+=../../shlr/yara/ops.o

CORE_SHARED2_YARA=$(addprefix ../,${CORE_SHARED_YARA})
CORE_OBJ_YARA+=${CORE_SHARED2_YARA}
CORE_SHARED2_YARA=

STATIC_OBJ+=${CORE_OBJ_YARA}
#SHARED_OBJ+=${CORE_OBJ_YARA}
CORE_TARGET_YARA=core_yara.${EXT_SO}

ALL_TARGETS+=${CORE_TARGET_YARA}

${CORE_TARGET_YARA}: ${CORE_OBJ_YARA}
	${CC} $(call libname,core_yara) ${CFLAGS} \
		-o core_yara.${EXT_SO} \
		${CORE_OBJ_YARA} ${CORE_SHARED2_YARA}
