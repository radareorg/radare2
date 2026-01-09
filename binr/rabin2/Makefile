BIN=rabin2
BINDEPS=r_magic r_core r_bin r_egg r_cons r_main
BINDEPS+=r_config r_io r_flag r_asm r_util r_bp r_reg
BINDEPS+=r_debug r_lang r_anal r_muta
BINDEPS+=r_search r_syscall r_socket r_fs r_magic

include ../rules.mk

include ../../libr/socket/deps.mk
include ../../libr/main/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/java/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/ar/deps.mk
include ../../shlr/capstone.mk

LDFLAGS+=$(LINK)
