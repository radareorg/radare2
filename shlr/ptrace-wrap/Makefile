include ../../libr/config.mk
include ../../mk/platform.mk

CC ?= gcc
AR ?= ar
RANLIB ?= ranlib
EXT_AR ?= a

CFLAGS+=-Iinclude
LIBPTRACE_WRAP=libptrace_wrap.${EXT_AR}

OFILES=src/ptrace_wrap.o

all: ${LIBPTRACE_WRAP}

%.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

${LIBPTRACE_WRAP}: $(OFILES)
	rm -f $(LIBPTRACE_WRAP)
	$(AR) q $(LIBPTRACE_WRAP) $(OFILES)
	$(RANLIB) $(LIBPTRACE_WRAP)

clean:
	rm -f $(OBJS) ${LIBPTRACE_WRAP} $(OFILES)
