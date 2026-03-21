# shlr/zip build configuration
# There is no bundled libzip or zlib - only system libzip is supported

include ../../config-user.mk
include ../../libr/config.mk
include ../../mk/platform.mk
include ../../mk/$(COMPILER).mk
include ../../shlr/sdb.mk
SHLR?=..

pre: all

include deps.mk

all:
	rm -f librz.$(EXT_AR)
ifneq ($(WANT_ZIP),1)
	@echo zip support disabled
else
ifeq ($(USE_LIB_ZIP),1)
	@echo no bundled zip to build
else
	$(MAKE) -C $(OTEZIP_ROOT) CC="$(CC)" EXT_AR="$(EXT_AR)" AR="$(AR)" RANLIB="$(RANLIB)" CFLAGS="$(CFLAGS) -fPIC" libotezip.$(EXT_AR)
endif
endif

clean:
	rm -f *.$(EXT_AR) *.${EXT_SO} $(OTEZIP_LIBA)
