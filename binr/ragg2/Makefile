BIN=ragg2
BINDEPS=r_egg r_syscall r_asm r_muta
BINDEPS+=r_core r_debug r_fs r_config
BINDEPS+=r_lang r_anal r_reg r_flag r_bp
BINDEPS+=r_bin r_search r_io r_socket
BINDEPS+=r_magic r_util r_main r_cons

include ../rules.mk
include ../../libr/main/deps.mk
include ../../shlr/ar/deps.mk
include ../../libr/socket/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/grub/deps.mk
include ../../shlr/java/deps.mk
include ../../shlr/capstone.mk
include ../../shlr/qnx/deps.mk

LDFLAGS+=$(LINK)
