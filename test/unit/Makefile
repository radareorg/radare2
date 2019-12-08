BINDIR := bin
BINS=$(patsubst %.c,$(BINDIR)/%,$(wildcard *.c))
LDFLAGS += $(shell pkg-config --libs r_core)
CFLAGS += $(shell pkg-config --cflags r_core) -g

all: $(BINS)

$(BINDIR)/%: %.c
	mkdir -p "$(BINDIR)"
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

run:
	r=0 ; for a in $(BINS) ; do ./$$a || r=1; done ; exit $r

clean:
	rm -f $(BINS)
	rm -fd "$(BINDIR)"

.PHONY: all
