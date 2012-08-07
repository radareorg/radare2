OBJ_ARM_WINEDBG=asm_arm_winedbg.o
OBJ_ARM_WINEDBG+=../arch/arm/winedbg/be_arm.o

STATIC_OBJ+=${OBJ_ARM_WINEDBG}
TARGET_ARM_WINEDBG=asm_arm_winedbg.${EXT_SO}

ALL_TARGETS+=${TARGET_ARM_WINEDBG}

${TARGET_ARM_WINEDBG}: ${OBJ_ARM_WINEDBG}
	${CC} $(call libname,asm_arm_winedbg) ${LDFLAGS} ${CFLAGS} -o asm_arm_winedbg.${EXT_SO} ${OBJ_ARM_WINEDBG}
