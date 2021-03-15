OBJ_RISCVPSEUDO+=parse_riscv_pseudo.o

TARGET_RISCVPSEUDO=parse_riscv_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_RISCVPSEUDO}
STATIC_OBJ+=${OBJ_RISCVPSEUDO}

ifeq ($(CC),cccl)
	RISCV_CFLAGS:=${CFLAGS}
	else
	RISCV_CFLAGS:=${CFLAGS} ${LINK}
	endif

${TARGET_RISCVPSEUDO}: ${OBJ_RISCVPSEUDO}
	${CC} $(call libname,parse_riscv_pseudo) -L../../util -lr_util \
		$(LDFLAGS_SHARED) ${RISCV_CFLAGS} -o ${TARGET_RISCVPSEUDO} ${OBJ_RISCVPSEUDO}

