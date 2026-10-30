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

anal-layout: anal-layout.c
	$(CC) $(CPPFLAGS) -O2 -I../../libr/include -I../../subprojects/sdb/include $< \
		-o $@ $(LDFLAGS) $(shell PKG_CONFIG_PATH="$(LIBDIR)/pkgconfig:$(PKG_CONFIG_PATH)" pkg-config --libs r_core)

.PHONY: clean-anal-layout
clean-anal-layout:
	rm -f anal-layout

anal-bb-storage: anal-bb-storage.c
	$(CC) $(CPPFLAGS) -O2 -I../../libr/include -I../../subprojects/sdb/include $< \
		-o $@ $(LDFLAGS) -L$(LIBDIR) -lr_util

.PHONY: clean-anal-bb-storage
clean-anal-bb-storage:
	rm -f anal-bb-storage

anal-bb-lookup: anal-bb-lookup.c
	$(CC) $(CPPFLAGS) -O2 -DBB_ORDER_CACHE=1 -I../../libr/include -I../../subprojects/sdb/include $< \
		-o $@ $(LDFLAGS) $(shell PKG_CONFIG_PATH="$(LIBDIR)/pkgconfig:$(PKG_CONFIG_PATH)" pkg-config --libs r_anal)

.PHONY: clean-anal-bb-lookup
clean-anal-bb-lookup:
	rm -f anal-bb-lookup
