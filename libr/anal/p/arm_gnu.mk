N=anal_arm_gnu
OBJ_ARM=anal_arm_gnu.o

STATIC_OBJ+=${OBJ_ARM}
TARGET_ARM=$(N).${EXT_SO}

CFLAGS+=-I$(LIBR)/asm/arch/include

ifeq ($(WITHPIC),1)
OBJ_ARM+=../../asm/arch/arm/winedbg/be_arm.o
endif

ALL_TARGETS+=${TARGET_ARM}

${TARGET_ARM}: ${OBJ_ARM}
	${CC} $(call libname,$(N)) ${LDFLAGS} ${CFLAGS} \
		-o $(TARGET_ARM) $(OBJ_ARM)
