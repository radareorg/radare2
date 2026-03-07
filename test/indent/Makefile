.PHONY: all clean

all: check-indent

check-indent: header.h source.c
	@echo "Checking indentation of header.h and source.c..."
	@if python3 ../../sys/clang-format-radare2 --no-update header.h source.c; then \
		echo "Indentation check passed!"; \
	else \
		echo "Indentation check failed!"; \
		exit 1; \
	fi

clean:
