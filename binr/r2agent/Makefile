include ../../config-user.mk
BIN=r2agent
BINDEPS=r_socket r_cons r_util r_main

ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
endif
include ../rules.mk
include ../../libr/main/deps.mk
include ../../shlr/java/deps.mk

LDFLAGS+=$(LINK)
