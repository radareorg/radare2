OBJ_XNU_KERNELCACHE=bin_xnu_kernelcache.o
OBJ_XNU_KERNELCACHE+=../format/xnu/yxml.o
OBJ_XNU_KERNELCACHE+=../format/xnu/r_cf_dict.o

STATIC_OBJ+=${OBJ_XNU_KERNELCACHE}
TARGET_XNU_KERNELCACHE=bin_xnu_kernelcache.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_XNU_KERNELCACHE}

${TARGET_XNU_KERNELCACHE}: ${OBJ_XNU_KERNELCACHE}
	-${CC} $(call libname,bin_xnu_kernelcache) -shared ${CFLAGS} \
	-o ${TARGET_XNU_KERNELCACHE} ${OBJ_XNU_KERNELCACHE} $(LINK) $(LDFLAGS) \
	${LDFLAGS_LINKPATH}../../syscall -L../../util -lr_syscall
endif
