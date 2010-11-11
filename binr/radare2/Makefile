BIN=radare2
BINDEPS=r_core r_parse r_search r_cons r_lib r_config r_diff
BINDEPS+=r_bin r_debug r_anal r_reg r_bp r_io r_cmd r_th r_vm
BINDEPS+=r_sign r_print r_lang r_asm r_syscall r_hash r_line r_socket r_flags r_util

include ../binr.mk

sign:
	ldid -Sradare2.xml radare2

ifeq ($(WITHNONPIC),1)
LDFLAGS+=${DL_LIBS} -lm -lpthread
ifeq ($(HAVE_LIB_GMP),1)
LDFLAGS+=-lgmp
endif
endif
