CORE_OBJ_JAVA=core_java.o

#CORE_SHARED_JAVA=../../shlr/java/code.o
#CORE_SHARED_JAVA+=../../shlr/java/class.o
#CORE_SHARED_JAVA+=../../shlr/java/ops.o

CORE_SHARED2_JAVA=$(addprefix ../,${CORE_SHARED_JAVA})
CORE_OBJ_JAVA+=${CORE_SHARED2_JAVA}
CORE_SHARED2_JAVA=

STATIC_OBJ+=${CORE_OBJ_JAVA}
#SHARED_OBJ+=${CORE_OBJ_JAVA}
CORE_TARGET_JAVA=core_java.${EXT_SO}
LDFLAGS+=$(LINK)

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${CORE_TARGET_JAVA}
R2DEPS+=r_crypto
include $(STOP)/java/deps.mk

${CORE_TARGET_JAVA}: ${CORE_OBJ_JAVA}
	echo ${CORE_OBJ_JAVA}
	${CC} $(call libname,core_java) ${CFLAGS} $(LDFLAGS) \
		-o core_java.${EXT_SO} \
		${CORE_OBJ_JAVA} ${CORE_SHARED2_JAVA} \
		$(SHLR)/java/libr_java.$(EXT_AR) \
		$(SHLR)/sdb/src/libsdb.$(EXT_AR) \
		-L$(LIBR)/crypto -lr_crypto
endif
