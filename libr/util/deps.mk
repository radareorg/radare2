include $(SHLR)/sdb.mk
include $(SHLR)/zip/deps.mk

ifneq (${BUILD_OS},darwin)
LDFLAGS+=-lm
endif

# NetBSD 7.0 ships with backtrace(3) in -lexecinfo
ifeq (${BUILD_OS},netbsd)
ifneq ($(shell expr "`uname -r`" : '[0-6]\.'), 2)
  LDFLAGS+=-lexecinfo
endif
endif

ifeq (${BUILD_OS},serenityos)
LDFLAGS+=
else
ifeq ($(OSTYPE),bsd)
LDFLAGS+=-lkvm
endif
endif

# FreeBSD 10.0 ships with backtrace(3) in -lexecinfo
ifeq (${BUILD_OS},freebsd)
  ifneq ($(shell expr "`uname -r`" : '[0-9]\.'), 2)
    LDFLAGS+=-lexecinfo
  endif
  LDFLAGS+=-lutil
endif

ifeq (${BUILD_OS},dragonfly)
  LDFLAGS+=-lexecinfo
endif

ifeq (${BUILD_OS},haiku)
  LDFLAGS+=-lexecinfo
endif

ifneq ($(OSTYPE),darwin)
ifneq ($(OSTYPE),haiku)
LDFLAGS+=-lm
LINK+=-lm
endif
endif

ifeq (${OSTYPE},aix)
LINK+=-pthread
endif
