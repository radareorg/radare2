# Link against system libzip when USE_LIB_ZIP=1
# Otherwise link against bundled otezip from subprojects/otezip
ifeq ($(USE_LIB_ZIP),1)
LINK+=$(LIBZIP)
else
# Build and link against bundled otezip
ifeq ($(_INCLUDE_OTEZIP_MK_),)
_INCLUDE_OTEZIP_MK_=1
OTEZIP_ROOT=$(SHLR)/../subprojects/otezip
OTEZIP_LIBA=$(OTEZIP_ROOT)/libotezip.a
CFLAGS+=-I$(OTEZIP_ROOT)/src/include/otezip
$(OTEZIP_LIBA):
	$(MAKE) -C $(OTEZIP_ROOT) CFLAGS="-fPIC" libotezip.a
endif
LINK+=$(OTEZIP_LIBA)
endif
