BIN=rabin2
BINDEPS=r_magic r_core r_bin r_egg r_cons r_main
BINDEPS+=r_config r_io r_flag r_asm
BINDEPS+=r_debug r_hash r_lang r_anal r_parse r_bp r_reg
BINDEPS+=r_search r_syscall r_socket r_fs r_magic r_crypto r_util

include ../rules.mk

include ../../libr/socket/deps.mk
include ../../libr/main/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/java/deps.mk
include ../../shlr/grub/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/ar/deps.mk
include ../../shlr/capstone.mk

LDFLAGS+=$(LINK)
