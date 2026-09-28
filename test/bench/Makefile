T=rarun2 time=true
F=../bins/elf/ls

all:
	for a in r2pipe/* ; do echo "[TT] $$a" ; $T system="r2 -qi $$a $F" > /dev/null ; done

-include ../../config-user.mk
STR_ANY_CFLAGS?=-O2

str_any: str_any.c ../../libr/include/r_util/r_str_any.h
	$(CC) $(CPPFLAGS) $(STR_ANY_CFLAGS) -I../../libr/include -I../../subprojects/sdb/include $< \
		-o $@ $(LDFLAGS) -L../../libr/util -lr_util

.PHONY: clean-str-any
clean-str-any:
	rm -f str_any
