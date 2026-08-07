ifeq ($(WANT_ZYDIS),1)

OBJ_X86_ZYDIS=p/x86/plugin_zydis.o
ZYDIS_LIB=$(ZYDIS_ROOT)/libzydis.a
ZYDIS_HDR=$(ZYDIS_ROOT)/amalgamated-dist/Zydis.h
ZYDIS_SRC=$(ZYDIS_ROOT)/amalgamated-dist/Zydis.c
ZYDIS_DEPS=

STATIC_OBJ+=$(OBJ_X86_ZYDIS)

TARGET_X86_ZYDIS=arch_x86_zydis.$(EXT_SO)

ALL_TARGETS+=${TARGET_X86_ZYDIS}

${OBJ_X86_ZYDIS}: CFLAGS += $(ZYDIS_CFLAGS)

ifneq ($(USE_ZYDIS),1)
ZYDIS_DEPS=$(ZYDIS_LIB)

${ZYDIS_LIB}: $(ZYDIS_SRC) $(ZYDIS_HDR)
	$(MAKE) -C $(LIBR)/../subprojects zydis CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)"

${OBJ_X86_ZYDIS}: ${ZYDIS_DEPS}
endif

${TARGET_X86_ZYDIS}: ${OBJ_X86_ZYDIS} ${ZYDIS_DEPS}
	${CC} ${CFLAGS} $(call libname,arch_x86_zydis) $(ZYDIS_CFLAGS) \
		-o arch_x86_zydis.${EXT_SO} ${OBJ_X86_ZYDIS} $(ZYDIS_LDFLAGS)

endif
