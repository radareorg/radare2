NAME=rz
LIBAR=librz.a

include ../../config-user.mk
include ../../libr/config.mk
include ../../mk/platform.mk
include ../../mk/${COMPILER}.mk

ifeq ($(USE_LIB_ZIP),1)
all:
	rm -f librz.a
else


LIBAR=librz.a
RANLIB?=ranlib

all: $(LIBAR)

$(LIBAR): zip/libr_zip.a
	${CC_AR} zlib/*.o zip/*.o
	$(RANLIB) librz.a

zip/libr_zip.a: zlib/libr_z.a
	$(MAKE) -C zip

zlib/libr_z.a:
	$(MAKE) -C zlib

clean:
	$(MAKE) -C zlib clean
	$(MAKE) -C zip clean
	rm -f *.a *.${EXT_SO} zlib/*.a zip/*.a
endif
