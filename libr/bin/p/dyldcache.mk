OBJ_DYLDCACHE=bin_dyldcache.o
# ../format/mach0/dyldcache.o

STATIC_OBJ+=${OBJ_DYLDCACHE}
TARGET_DYLDCACHE=bin_dyldcache.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_DYLDCACHE}

${TARGET_DYLDCACHE}: ${OBJ_DYLDCACHE}
	-${CC} $(call libname,bin_dyldcache) -shared ${CFLAGS} \
	-o ${TARGET_DYLDCACHE} ${OBJ_DYLDCACHE} $(LINK) $(LDFLAGS)
endif
