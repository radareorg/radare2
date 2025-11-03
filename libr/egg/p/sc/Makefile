SRCS  := $(shell cd src ; ls *.c)
SCS := $(subst .c,,$(notdir $(SRCS)))
PYTHON3?=python3
HAVE_PYTHON=$(shell $(PYTHON3) --version > /dev/null 2>&1 && echo 1)

all: out
	@echo HAVE_PYTHON=$(HAVE_PYTHON)

out:
ifeq ($(HAVE_PYTHON),1)
	$(PYTHON3) scmangle.py --out-dir out/ src/*
else
	rm -rf out
	mkdir -p out
	cp -rf src/*.c out
	echo 'static inline ut8 *sc_decrypt(const ut8 *buf, size_t len) { return r_mem_dup (buf, len); }' > out/decrypt.inc.c
endif

clean:
	rm -rf out
	rm -f *.c

# Test target: verify rasm2 output matches original shellcodes
test: test-shellcodes

test-shellcodes:
	@echo "Testing shellcode assembly..."
	@fail=0; \
	for rasm in asm/*.rasm; do \
		base=$$(basename $$rasm .rasm); \
		src_file="src/$$base.c"; \
		if [ -f "$$src_file" ]; then \
			expected=$$(awk '/^#if 0/,/^#endif/{next} /\\x/{gsub(/^\/\*.*\*\/ /, ""); print}' "$$src_file" | grep -o '"\\x[^"]*"' | sed 's/"//g; s/\\x//g' | tr -d '\n'); \
			case "$$base" in \
				x86-linux-binsh) \
					actual=$$(rasm2 -a x86 -b 32 -f "$$rasm" 2>/dev/null); \
					;; \
				x86_64-linux-binsh) \
					actual=$$(rasm2 -a x86 -b 64 -f "$$rasm" 2>/dev/null); \
					;; \
				x86-osx-binsh|x86-osx-suidbinsh) \
					actual=$$(rasm2 -a x86 -b 64 -f "$$rasm" 2>/dev/null); \
					;; \
				arm-linux-binsh) \
					actual=$$(rasm2 -a arm -b 32 -f "$$rasm" 2>/dev/null); \
					;; \
				thumb-linux-binsh) \
					actual=$$(rasm2 -a arm -f "$$rasm" 2>/dev/null); \
					;; \
				*) \
					echo "  ⚠️  $$base: Unknown architecture, skipping"; \
					continue; \
					;; \
			esac; \
			if [ "$$actual" = "$$expected" ]; then \
				echo "  ✓  $$base: PASS ($$actual)"; \
			else \
				echo "  ✗  $$base: FAIL"; \
				echo "     Expected: $$expected"; \
				echo "     Got:      $$actual"; \
				fail=$$((fail + 1)); \
			fi; \
		else \
			echo "  ⚠️  $$base: No source file found, skipping"; \
		fi; \
	done; \
	if [ $$fail -eq 0 ]; then \
		echo "All tests passed! ✓"; \
	else \
		echo "$$fail test(s) failed ✗"; \
		exit 1; \
	fi

.PHONY: all clean test test-shellcodes
