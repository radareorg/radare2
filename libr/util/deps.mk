include $(SHLR)/sdb.mk
include $(SHLR)/zip/deps.mk

LDFLAGS+=-lm

# NetBSD 7.0 ships with backtrace(3) in -lexecinfo
ifeq (${BUILD_OS},netbsd)
ifneq ($(shell expr "`uname -r`" : '[0-6]\.'), 2)
  LDFLAGS+=-lexecinfo
endif
endif

# FreeBSD 10.0 ships with backtrace(3) in -lexecinfo
ifeq (${BUILD_OS},freebsd)
ifneq ($(shell expr "`uname -r`" : '[0-9]\.'), 2)
  LDFLAGS+=-lexecinfo
endif
endif

ifeq (${BUILD_OS},dragonfly)
  LDFLAGS+=-lexecinfo
endif

ifeq (${BUILD_OS},haiku)
  LDFLAGS+=-lexecinfo
endif
