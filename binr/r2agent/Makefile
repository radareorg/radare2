include ../../config-user.mk
BIN=r2agent
BINDEPS=r_socket r_cons r_util

ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
endif

include ../rules.mk
