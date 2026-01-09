BIN=rapatch2

BINDEPS=r_core r_search r_cons r_config
BINDEPS+=r_bin r_debug r_anal r_reg r_bp r_io r_fs
BINDEPS+=r_lang r_asm r_syscall r_main r_util r_esil
BINDEPS+=r_magic r_socket r_flag r_egg r_muta

include ../rules.mk

ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
endif

include ../../libr/socket/deps.mk
include ../../libr/main/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk

LDFLAGS+=$(LINK)
