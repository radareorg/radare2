include ../../config-user.mk

all: libr_zip.a libr_zip.${SOEXT}

libr_zip.a libr_zip.${SOEXT}:
	${MAKE} -C zlib
	${MAKE} -C zip

clean:
	${MAKE} -C zlib clean
	${MAKE} -C zip clean
	rm *.a *.${SOEXT}
