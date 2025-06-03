BIN=rafind2

BINDEPS=r_search r_io r_asm r_anal r_reg r_cons r_muta
BINDEPS+=r_socket r_util r_syscall r_flag r_main r_lang

include ../rules.mk

include ../../libr/socket/deps.mk
include ../../libr/main/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/ar/deps.mk

LDFLAGS+=$(LINK)
