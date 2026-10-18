CORE_OBJ_JAVA=core_java.o

STATIC_OBJ+=${CORE_OBJ_JAVA}
CORE_TARGET_JAVA=core_java.${EXT_SO}
LDFLAGS+=$(LINK)

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${CORE_TARGET_JAVA}
R2DEPS+=r_muta
include $(STOP)/java/deps.mk

${CORE_TARGET_JAVA}: ${CORE_OBJ_JAVA}
	echo ${CORE_OBJ_JAVA}
	${CC} $(call libname,core_java) ${CFLAGS} $(LDFLAGS) \
		-o core_java.${EXT_SO} \
		${CORE_OBJ_JAVA} \
		$(SHLR)/java/libr_java.$(EXT_AR) \
		$(SHLR)/../subprojects/sdb/src/libsdb.$(EXT_AR)
endif
