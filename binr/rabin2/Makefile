BIN=rabin2
BINDEPS=r_bin r_cons r_util r_lib r_flags r_db
# rapatch deps
BINDEPS+=r_core r_parse r_search r_lib r_config r_diff
BINDEPS+=r_debug r_anal r_reg r_bp r_io r_cmd r_fs r_line
BINDEPS+=r_sign r_print r_lang r_asm r_syscall r_hash r_socket 

include ../binr.mk

ifeq ($(WITHNONPIC),1)
LDFLAGS+=${DL_LIBS}
endif
