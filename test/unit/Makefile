BINDIR := bin
BINS=$(patsubst %.c,$(BINDIR)/%,$(wildcard *.c))
LDFLAGS+=$(shell pkg-config --libs r_core)
CFLAGS+=-I../../libr/include
CFLAGS+=-I../../shlr/sdb/src
CFLAGS+=-g
ifeq ($(ASAN),1)
	ASAN_LD_PRELOAD=LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.5
else
	ASAN_LD_PRELOAD=
endif

all: $(BINS)

asan:
	$(MAKE) ASAN=1

$(BINDIR)/%: %.c
	mkdir -p "$(BINDIR)"
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

run: $(BINS)
	r=0 ; cd .. ; for a in $(BINS) ; do echo "$$a" ; $(ASAN_LD_PRELOAD) ./unit/$$a || r=1; done ; echo unit$$r ; exit $$r

clean:
	rm -f $(BINS)
	rm -fd "$(BINDIR)"

.PHONY: all
