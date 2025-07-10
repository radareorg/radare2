NAME=rz
LIBAR=librz.$(EXT_AR)

# libzip = 1.9.2
# zlib = 1.2.12

include ../../config-user.mk
include ../../libr/config.mk
include ../../mk/platform.mk
include ../../mk/$(COMPILER).mk
include ../../shlr/sdb.mk

ifeq ($(USE_LIB_ZIP),1)
all:
	rm -f librz.$(EXT_AR)
else

LIBAR=librz.$(EXT_AR)
RANLIB?=ranlib

all: $(LIBAR)

$(LIBAR): $(SPRJ)/zip/libr_zip.$(EXT_AR)
	@echo ${CC_AR} $(SPRJ)/zlib/*.o $(SPRJ)/zip/lib/*.o
	${CC_AR} $(SPRJ)/zlib/*.o $(SPRJ)/zip/lib/*.o
	@echo $(RANLIB) librz.$(EXT_AR)
	$(RANLIB) librz.$(EXT_AR)

$(SPRJ)/zip/libr_zip.$(EXT_AR): $(SPRJ)/zlib/libr_z.$(EXT_AR)
	$(MAKE) -C $(SPRJ)/zip

$(SPRJ)/zlib/libr_z.$(EXT_AR):
	$(MAKE) -C $(SPRJ)/zlib

clean:
	$(MAKE) -C $(SPRJ)/zlib clean
	$(MAKE) -C $(SPRJ)/zip clean
	rm -f *.$(EXT_AR) *.${EXT_SO} $(SPRJ)/zlib/*.$(EXT_AR) $(SPRJ)/zip/*.$(EXT_AR)
endif
