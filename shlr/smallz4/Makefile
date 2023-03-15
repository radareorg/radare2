CFLAGS = -O2 -Wall -pedantic -s -std=c99

smallz4cat.o:
	$(CC) $(CCFLAGS) $(EXTRAFLAGS) -c smallz4cat.c

all32: CFLAGS+=-m32

.PHONY: clean
clean:
	@$(RM) *.o
