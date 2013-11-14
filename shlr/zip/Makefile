include ../../config-user.mk
include ../../libr/config.mk
include ../../mk/${COMPILER}.mk

all: librz.a

LIBAR=librz.a
librz.a: libr_zip.a
	${CC_AR} zlib/*.o zip/*.o

libr_zip.a: libr_z.a
	${MAKE} -C zip

libr_z.a:
	${MAKE} -C zlib

clean:
	${MAKE} -C zlib clean
	${MAKE} -C zip clean
	rm -f *.a *.${EXT_SO}
