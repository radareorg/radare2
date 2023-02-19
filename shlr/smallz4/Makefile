CFLAGS = -O2 -Wall -pedantic -s -std=c99

smallz4cat.o:
	$(CC) $(CCFLAGS) $(EXTRAFLAGS) -c smallz4cat.c

all32: CFLAGS+=-m32

sync:
	rm -f smallz4cat.c
	# Github repo is more up to date despite being a mirror
	wget https://raw.githubusercontent.com/stbrumme/smallz4/master/smallz4cat.c
	patch -p1 <unlz4block.patch

.PHONY: clean
clean:
	@$(RM) *.o

