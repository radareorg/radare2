.PHONY: zydis zydis_clean

# Zydis is vendored in-tree and unpatched, see ZYDIS.md. Nothing to download,
# unpack or patch here: just build the single amalgamated translation unit.
ZYDIS_BUILD_CFLAGS=$(filter-out -Werror%,$(CFLAGS))

zydis: zydis/libzydis.a

zydis/libzydis.a: zydis/Zydis.o
	${AR} rcs zydis/libzydis.a zydis/Zydis.o

zydis/Zydis.o: zydis/amalgamated-dist/Zydis.c zydis/amalgamated-dist/Zydis.h
	${CC} ${ZYDIS_BUILD_CFLAGS} -fPIC -DZYDIS_STATIC_BUILD -Izydis/amalgamated-dist -c zydis/amalgamated-dist/Zydis.c -o zydis/Zydis.o

zydis_clean:
	rm -f zydis/Zydis.o zydis/libzydis.a
