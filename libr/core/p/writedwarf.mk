CORE_OBJ_MAKEDWARF=core_writedwarf.o

CORE_SHARED2_MAKEDWARF=$(addprefix ../,${CORE_SHARED_MAKEDWARF})
CORE_OBJ_MAKEDWARF+=${CORE_SHARED2_MAKEDWARF}
CORE_SHARED2_MAKEDWARF=

STATIC_OBJ+=${CORE_OBJ_MAKEDWARF}
#SHARED_OBJ+=${CORE_OBJ_MAKEDWARF}
CORE_TARGET_MAKEDWARF=core_writedwarf.${EXT_SO}
LDFLAGS+=$(LINK)

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${CORE_TARGET_MAKEDWARF}
R2DEPS+=r_codec
include $(STOP)/writedwarf/deps.mk

${CORE_TARGET_MAKEDWARF}: ${CORE_OBJ_MAKEDWARF}
	echo ${CORE_OBJ_MAKEDWARF}
	${CC} $(call libname,core_writedwarf) ${CFLAGS} $(LDFLAGS) \
		-o core_writedwarf.${EXT_SO} \
		${CORE_OBJ_MAKEDWARF} ${CORE_SHARED2_MAKEDWARF} \
		$(SHLR)/writedwarf/libr_writedwarf.$(EXT_AR) \
		$(SHLR)/../subprojects/sdb/src/libsdb.$(EXT_AR)
endif
