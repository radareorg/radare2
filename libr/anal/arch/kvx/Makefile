kv3.opc: kv3-opc.c  opc.sed anal.sed arg.sed
	./opc.sed $< | ./anal.sed | ./arg.sed > $@
kv3-opc.c:
	curl https://raw.githubusercontent.com/kalray/gdb-binutils/binutils-2_35_2/coolidge/opcodes/kv3-opc.c > $@
