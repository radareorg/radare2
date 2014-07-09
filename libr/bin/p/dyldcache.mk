OBJ_DYLDCACHE=bin_xtr_dyldcache.o ../format/mach0/dyldcache.o

STATIC_OBJ+=${OBJ_DYLDCACHE}
TARGET_DYLDCACHE=bin_xtr_dyldcache.${EXT_SO}

ALL_TARGETS+=${TARGET_DYLDCACHE}

${TARGET_DYLDCACHE}: ${OBJ_DYLDCACHE}
	-${CC} $(call libname,bin_xtr_dyldcache) -shared ${CFLAGS} \
	-o ${TARGET_DYLDCACHE} ${OBJ_DYLDCACHE} $(LINK) $(LDFLAGS)
