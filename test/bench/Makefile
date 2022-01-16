T=rarun2 time=true
F=../bins/elf/ls

all:
	for a in r2pipe/* ; do echo "[TT] $$a" ; $T system="r2 -qi $$a $F" > /dev/null ; done
