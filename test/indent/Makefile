.PHONY: all clean check-indent format

all: check-indent

check-indent: header.h source.c
	@echo "Checking indentation of header.h and source.c..."
	@if python3 ../../sys/clang-format-radare2 --no-update header.h source.c; then \
		echo "Indentation check passed!"; \
	else \
		echo "Indentation check failed!"; \
		exit 1; \
	fi

format: header.h source.c
	@echo "Formatting header.h and source.c..."
	python3 ../../sys/clang-format-radare2 -i header.h source.c

clean:
