UNITS_BINDIR := bin
BINS=$(patsubst %.c,$(UNITS_BINDIR)/%,$(wildcard *.c))
# LDFLAGS+=$(shell pkg-config --libs r_core)
-include ../../config-user.mk
LDFLAGS+=-L$(LIBDIR)
LDFLAGS+=-lr_core -lr_main -lm -lr_config -lr_debug -lr_bin -lr_lang -lr_anal -lr_bp -lr_egg -lr_asm -lr_flag -lr_search -lr_syscall -lr_fs -lr_io -lr_socket -lr_cons -lr_magic -lr_muta -lr_arch -lr_esil -lr_reg -lr_util -ldl
CFLAGS+=-I$(INCLUDEDIR)
CFLAGS+=-I../../libr/include
CFLAGS+=-I../../subprojects/sdb/include
CFLAGS+=-g
ifeq ($(ASAN),1)
	ASAN_LD_PRELOAD=LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.5
else
	ASAN_LD_PRELOAD=
endif

all: $(BINS)

asan:
	CFLAGS=-fsanitize=address $(MAKE) ASAN=1

$(UNITS_BINDIR)/%: %.c
	mkdir -p "$(UNITS_BINDIR)"
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

test_debug: $(UNITS_BINDIR)/test_debug
	@:

run: $(BINS)
	@export R2_DEBUG_ASSERT=1 ; R=0 ; r=0 ; cd .. ; \
	  for a in $(BINS) ; do \
	  	echo "$$a" ; \
		R=0 ; $(ASAN_LD_PRELOAD) ./unit/$$a || R=1; \
		if [ "$$R" = 1 ]; then r=1; echo '[X''X]'; fi; \
	  done ; \
	echo unit$$r ; exit $$r

clean:
	rm -f $(BINS)
	-rm -fd "$(UNITS_BINDIR)"

.PHONY: all
