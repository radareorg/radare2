include ../../config.mk
include ../../../mk/platform.mk

LINK+=-L../../util -lr_util
LDFLAGS+=${LINK}

ifeq ($(WITHPIC),1)
all: ${ALL_TARGETS}

ALL_TARGETS=
CFLAGS+=-I../../include
#ALGOS=aes.mk aes_cbc.mk
include add.mk
include aes.mk
include aes_cbc.mk
include aes_wrap.mk
include base64.mk
include base91.mk
include bech32.mk
include blowfish.mk
include cps2.mk
include des.mk
include ed25519.mk
include entropy.mk
include null.mk
include punycode.mk
include rc2.mk
include rc4.mk
include rc6.mk
include rot.mk
include serpent.mk
include sip.mk
include sm4.mk
include strhash.mk
include md5.mk
include sha.mk
include xor.mk
include charset_pokemon.mk
include charset_ascii.mk
include charset_ebcdic37.mk
include charset_iso8859_1.mk
include charset_hiragana.mk
include charset_katakana.mk
include charset_pokered.mk
include charset_arabic_iso.mk
include charset_arabic_windows.mk
include charset_ascii_ansi.mk
include charset_ascii_oem.mk
include charset_big5.mk
include charset_cyrillic_iso.mk
include charset_cyrillic_windows.mk
include charset_greek_iso.mk
include charset_greek_windows.mk
include charset_hebrew_iso.mk
include charset_hebrew_windows.mk
include charset_iso_646.mk
include charset_jis7.mk
include charset_macintosh.mk

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d

.PHONY: all clean mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
