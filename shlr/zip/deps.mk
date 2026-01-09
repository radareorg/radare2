# Link against system libzip when USE_LIB_ZIP=1
# Otherwise link against bundled otezip from subprojects/otezip
ifeq ($(USE_LIB_ZIP),1)
LINK+=$(LIBZIP)
else
_INCLUDE_OTEZIP_MK_=1
OTEZIP_ROOT=$(SHLR)/../subprojects/otezip
OTEZIP_LIBA=$(OTEZIP_ROOT)/libotezip.$(EXT_AR)
CFLAGS+=-I$(OTEZIP_ROOT)/src/include/otezip
$(OTEZIP_LIBA):
	$(MAKE) -C $(OTEZIP_ROOT) CC="$(CC)" EXT_AR="$(EXT_AR)" AR="$(AR)" RANLIB="$(RANLIB)" CFLAGS="$(CFLAGS) -fPIC" libotezip.$(EXT_AR)
LINK+=$(OTEZIP_LIBA)
endif
