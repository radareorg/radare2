T=asm echo write undo redo math

all: ${T}

${T}:
	@cd t ; ./$@
	@#@cd t ; for a in ${T} ; do ./$$a ; done

clean:
	rm -f t/out.* t/rad.*

.PHONY: all ${T} clean
