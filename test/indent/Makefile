.PHONY: all clean check-indent format
FMT=../../sys/clang-format-radare2

all: check-indent

check-indent: header.h source.c
	$(FMT) --no-update header.h source.c

format: header.h source.c
	$(FMT) header.h source.c

clean:
	rm -f header.h source.c
	git checkout header.h source.c
