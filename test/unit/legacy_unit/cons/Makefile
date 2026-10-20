CFLAGS+=-I../../include
LDFLAGS+=-lr_cons -L../../libr/cons
LDFLAGS+=-lr_util -L../../libr/util

all: graph test-rgb

test-rgb: test-rgb.o
	$(CC) -o test-rgb test-rgb.o $(LDFLAGS)

graph: graph.o
	$(CC) -o graph graph.o $(LDFLAGS)
