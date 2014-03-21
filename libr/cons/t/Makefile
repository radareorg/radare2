CFLAGS+=-I../../include
LDFLAGS+=-lr_cons -L../../libr/cons
LDFLAGS+=-lr_util -L../../libr/util

all:
	$(CC) -o editor editor.c $(CFLAGS) $(LDFLAGS)
	$(CC) -o test-rgb test-rgb.c $(CFLAGS) $(LDFLAGS)
