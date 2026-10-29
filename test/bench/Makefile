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

ansi_crop: ansi_crop.c
	$(CC) $(CPPFLAGS) -O2 -I../../libr/include -I../../subprojects/sdb/include $< \
		-o $@ $(LDFLAGS) -L../../libr/util -lr_util

.PHONY: clean-ansi-crop
clean-ansi-crop:
	rm -f ansi_crop

strpool: strpool.c
	$(CC) $(CPPFLAGS) -O2 -I../../libr/include -I../../subprojects/sdb/include $< \
		-o $@ $(LDFLAGS) -L../../libr/util -lr_util

.PHONY: clean-strpool
clean-strpool:
	rm -f strpool

asm_code: asm_code.c
	$(CC) $(CPPFLAGS) -O2 -I../../libr/include -I../../subprojects/sdb/include $< \
		-o $@ $(LDFLAGS) -L../../libr/asm -lr_asm -L../../libr/util -lr_util

.PHONY: clean-asm-code
clean-asm-code:
	rm -f asm_code
