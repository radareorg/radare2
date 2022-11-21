LIBEXT=$(shell r2 -H LIBEXT)
R2_LIBR_PLUGINS=$(shell r2 -H R2_LIBR_PLUGINS)

all:
	for a in asm anal bin ; do $(MAKE) -C $$a ; done

clean:
	for a in asm anal bin ; do $(MAKE) -C $$a clean ; done

install:
	mkdir -p $(R2_LIBR_PLUGINS)
	cp -f {asm,anal,bin}/*.$(LIBEXT) ${R2_LIBR_PLUGINS}/

uninstall:
	rm -f $(R2_LIBR_PLUGINS)/*lua53*.$(LIBEXT)
