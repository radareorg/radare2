LANG=guile
LANG_EXT=scm
LIBS_PFX=

include ../rules.mk

patch:
	cd ../ ; patch -p2 < guile/vapi.patch

unpatch:
	cd ../ ; patch -R -p2 < guile/vapi.patch

run:
	GUILE_WARN_DEPRECATED=no guile test-asm.scm
	GUILE_WARN_DEPRECATED=no guile test-util.scm
