MAIN_LINK_ALL=1

ifeq ($(MAIN_LINK_ALL),1)
R2DEPS=r_config r_cons r_io r_util r_flag r_asm r_core r_arch
R2DEPS+=r_debug r_bin r_lang r_io r_anal r_bp r_egg r_esil
R2DEPS+=r_reg r_search r_syscall r_socket r_fs r_magic r_muta
else
# only works
WITH_LIBS=0
WITH_LIBR=1
endif
