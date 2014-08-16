include ../../config-user.mk
include ../../libr/config.mk
include ../../mk/${COMPILER}.mk

ifeq ($(USE_LIB_ZIP),1)
all:
	rm -f librz.a
else


LIBAR=librz.a

all: $(LIBAR)

$(LIBAR): zip/libr_zip.a
	${CC_AR} zlib/*.o zip/*.o

zip/libr_zip.a: zlib/libr_z.a
	$(MAKE) -C zip

zlib/libr_z.a:
	$(MAKE) -C zlib

clean:
	$(MAKE) -C zlib clean
	$(MAKE) -C zip clean
	rm -f *.a *.${EXT_SO}
endif
