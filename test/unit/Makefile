BINDIR := bin
BINS=$(patsubst %.c,$(BINDIR)/%,$(wildcard *.c))
LDFLAGS += $(shell pkg-config --libs r_core)
CFLAGS += $(shell pkg-config --cflags r_core) -g

all: $(BINS)

$(BINDIR)/%: %.c
	mkdir -p "$(BINDIR)"
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

run:
	r=0 ; cd .. ; for a in $(BINS) ; do ./unit/$$a || r=1; done ; echo unit$$r ; exit $$r

clean:
	rm -f $(BINS)
	rm -fd "$(BINDIR)"

.PHONY: all
