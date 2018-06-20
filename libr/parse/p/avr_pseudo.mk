OBJ_AVRPSEUDO+=parse_avr_pseudo.o

TARGET_AVRPSEUDO=parse_avr_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_AVRPSEUDO}
STATIC_OBJ+=${OBJ_AVRPSEUDO}

${TARGET_AVRPSEUDO}: ${OBJ_AVRPSEUDO}
ifeq ($(CC),cccl)
	${CC} $(call libname,parse_avr_pseudo) -L../../util -llibr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_AVRPSEUDO} ${OBJ_AVRPSEUDO}
else
	${CC} $(call libname,parse_avr_pseudo) -L../../util -lr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_AVRPSEUDO} ${OBJ_AVRPSEUDO} $(LINK)
endif
