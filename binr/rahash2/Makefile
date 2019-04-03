BIN=rahash2

BINDEPS=r_main

include ../rules.mk

ifeq ($(OSTYPE),android)
LDFLAGS+=-lm
endif

include ../../libr/socket/deps.mk
include ../../libr/main/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/ar/deps.mk

LDFLAGS+=$(LINK)
