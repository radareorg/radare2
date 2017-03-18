OBJECTS = $(patsubst %.c,%,$(wildcard *.c))
LDFLAGS += $(shell pkg-config --libs r_util)
CFLAGS += $(shell pkg-config --cflags r_util) -g

all: $(OBJECTS)

$(OBJECTS):%:%.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

run:
	r=0 ; for a in $(OBJECTS) ; do ./$$a || r=1; done ; exit $r

clean:
	rm -f $(OBJECTS)

.PHONY: all $(OBJECTS)
