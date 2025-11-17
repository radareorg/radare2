# LIBEXT=$(shell r2 -HR2_LIBEXT)
# CFLAGS+=$(shell pkg-config --cflags r_core) -fPIC
# LDFLAGS+=$(shell pkg-config --libs r_core) -fPIC
# R2_USER_PLUGINS=$(shell r2 -HR2_USER_PLUGINS)

# CORE_HELLO=src/core_hello.$(LIBEXT)
# OBJS=src/core_hello.o

# all: $(CORE_HELLO)

# $(CORE_HELLO): $(OBJS)
# 	r2pm -r $(CC) $(LDFLAGS) -shared -fPIC  -o $(CORE_HELLO) $(OBJS)

# clean:
# 	rm -f $(OBJS) $(CORE_HELLO)

# user-install install:
# 	mkdir -p $(R2_USER_PLUGINS)
# 	cp -f $(CORE_HELLO) $(R2_USER_PLUGINS)

# user-uninstall uninstall:
# 	rm -f $(R2_USER_PLUGINS)/$(CORE_HELLO)

LIBEXT=$(shell r2 -HR2_LIBEXT)
CFLAGS+=$(shell pkg-config --cflags r_core) -fPIC
LDFLAGS+=$(shell pkg-config --libs r_core) -fPIC
R2_USER_PLUGINS=$(shell r2 -HR2_USER_PLUGINS)

# Unicorn Engine detection and flags
UNICORN_CFLAGS=$(shell pkg-config --cflags unicorn 2>/dev/null || echo "-I/usr/local/include -I/usr/include")
UNICORN_LIBS=$(shell pkg-config --libs unicorn 2>/dev/null || echo "-lunicorn")

# Check if unicorn is available
UNICORN_AVAILABLE=$(shell echo '\#include <unicorn/unicorn.h>' | $(CC) $(UNICORN_CFLAGS) -E - >/dev/null 2>&1 && echo "yes" || echo "no")

CFLAGS+=$(UNICORN_CFLAGS)
LDFLAGS+=$(UNICORN_LIBS)

CORE_ARM64EMU=src/core_arm64emu.$(LIBEXT)
OBJS=src/core_arm64emu.o

all: check-unicorn $(CORE_ARM64EMU)

check-unicorn:
ifeq ($(UNICORN_AVAILABLE),no)
	@echo "Error: Unicorn Engine not found!"
	@echo "Please install Unicorn Engine development headers:"
	@echo "  Ubuntu/Debian: sudo apt-get install libunicorn-dev"
	@echo "  macOS: brew install unicorn"
	@echo "  From source: https://github.com/unicorn-engine/unicorn"
	@exit 1
endif

$(CORE_ARM64EMU): $(OBJS)
	r2pm -r $(CC) $(LDFLAGS) -shared -fPIC -o $(CORE_ARM64EMU) $(OBJS)

src/core_arm64emu.o: src/core_arm64emu.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(CORE_ARM64EMU)

user-install install: $(CORE_ARM64EMU)
	mkdir -p $(R2_USER_PLUGINS)
	cp -f $(CORE_ARM64EMU) $(R2_USER_PLUGINS)

user-uninstall uninstall:
	rm -f $(R2_USER_PLUGINS)/core_arm64emu.$(LIBEXT)

.PHONY: all clean install uninstall user-install user-uninstall check-unicorn