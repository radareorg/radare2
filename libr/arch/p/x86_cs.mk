OBJ_X86_CS=p/x86/plugin_cs.o

STATIC_OBJ+=$(OBJ_X86_CS)

ifneq ($(filter p/x86_zydis.mk,$(STATIC_ARCH_PLUGINS)),)
${OBJ_X86_CS}: CFLAGS += -DR2_X86_ZYDIS_ENABLED=1
else
${OBJ_X86_CS}: CFLAGS += -DR2_X86_ZYDIS_ENABLED=0
endif

TARGET_X86_CS=arch_x86_cs.$(EXT_SO)

ALL_TARGETS+=${TARGET_X86_CS}

${TARGET_X86_CS}: ${OBJ_X86_CS}
	${CC} ${CFLAGS} $(call libname,arch_x86_cs) $(CS_CFLAGS) \
		-o arch_x86_cs.${EXT_SO} ${OBJ_X86_CS} $(CS_LDFLAGS)
