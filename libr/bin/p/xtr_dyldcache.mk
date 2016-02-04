OBJ_XTR_DYLDCACHE=bin_xtr_dyldcache.o ../format/mach0/dyldcache.o

STATIC_OBJ+=${OBJ_XTR_DYLDCACHE}
TARGET_XTR_DYLDCACHE=bin_xtr_dyldcache.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_XTR_DYLDCACHE}

${TARGET_XTR_DYLDCACHE}: ${OBJ_XTR_DYLDCACHE}
	-${CC} $(call libname,bin_xtr_dyldcache) -shared ${CFLAGS} \
	-o ${TARGET_XTR_DYLDCACHE} ${OBJ_XTR_DYLDCACHE} $(LINK) $(LDFLAGS)
endif
