.PHONY: zydis zydis_clean

ZYDIS_BUILD_CFLAGS=$(filter-out -Werror%,$(CFLAGS))
ZYDIS_PATCHES=zydis-patches/unused-rex-token-aliases.patch

zydis:
	rm -rf zydis.tmp
	mkdir -p zydis.tmp
	cp -rf packagefiles/zydis/* zydis.tmp
	for a in ${ZYDIS_PATCHES}; do \
		echo "patch -d zydis.tmp -p1 < zydis.tmp/$$a" ; \
		patch -d zydis.tmp -p1 < zydis.tmp/$$a ; \
	done
	${CC} ${ZYDIS_BUILD_CFLAGS} -fPIC -DZYDIS_STATIC_BUILD -Izydis.tmp/amalgamated-dist -c zydis.tmp/amalgamated-dist/Zydis.c -o zydis.tmp/Zydis.o
	${AR} rcs zydis.tmp/libzydis.a zydis.tmp/Zydis.o
	rm -rf zydis
	mv zydis.tmp zydis

zydis_clean:
	rm -rf zydis zydis.tmp
