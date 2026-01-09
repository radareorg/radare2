# shlr/zip build configuration
# There is no bundled libzip or zlib - only system libzip is supported

include ../../config-user.mk
include ../../libr/config.mk
include ../../mk/platform.mk
include ../../mk/$(COMPILER).mk
include ../../shlr/sdb.mk

all:
	rm -f librz.$(EXT_AR)
ifeq ($(USE_LIB_ZIP),1)
	@echo no bundled zip to build
else
	$(MAKE) $(OTEZIP_LIBA)
endif

include deps.mk

clean:
	rm -f *.$(EXT_AR) *.${EXT_SO} $(OTEZIP_LIBA)
