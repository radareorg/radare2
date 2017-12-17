MODS=parse syscall reg bp anal util asm magic bin
MODS+=config socket search crypto hash io fs lang

all: tmp out

out:
	mkdir out
	for a in ${MODS} ; do sh apia.sh $$a > out/$$a.txt ; done

tmp:
	./apis.sh

clean:
	rm -rf tmp
