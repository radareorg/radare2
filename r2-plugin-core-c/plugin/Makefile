# Makefile for Enhanced Ptrace IO Plugin
LIBEXT=$(shell r2 -HR2_LIBEXT)
CFLAGS+=$(shell pkg-config --cflags r_io) -fPIC
LDFLAGS+=$(shell pkg-config --libs r_io) -fPIC
R2_USER_PLUGINS=$(shell r2 -HR2_USER_PLUGINS)

TARGET=io_ptrace_enhanced.$(LIBEXT)
OBJS=io_ptrace_enhanced.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -shared -fPIC -o $(TARGET) $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)

install user-install:
	mkdir -p $(R2_USER_PLUGINS)
	cp -f $(TARGET) $(R2_USER_PLUGINS)

uninstall user-uninstall:
	rm -f $(R2_USER_PLUGINS)/$(TARGET)

test:
	# Test the plugin after installation
	@echo "Testing plugin installation..."
	@r2 -L | grep ptrace_enhanced || echo "Plugin not found in listing"
	@echo "Try: r2 ptrace://PID"

.PHONY: all clean install uninstall test user-install user-uninstall
