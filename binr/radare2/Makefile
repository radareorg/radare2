BIN=radare2
BINDEPS=r_core r_parse r_search r_cons r_lib r_config r_diff
BINDEPS+=r_bin r_debug r_anal r_reg r_bp r_io r_cmd r_fs r_db
BINDEPS+=r_sign r_print r_lang r_asm r_syscall r_hash r_line r_socket r_flags r_util

include ../binr.mk

sign:
	ldid -Sradare2.xml radare2

osxsign:
	${CC} radare2.o ${CFLAGS} ${LDFLAGS} -sectcreate __TEXT __info_plist ./Info.plist -o radare2 -framework Security -framework CoreFoundation
	codesign -dvvv -s radare2 ./radare2
	sudo chown root:procmod radare2
	sudo chmod g+s radare2

ifeq ($(WITHNONPIC),1)
LDFLAGS+=${DL_LIBS} -lm
LDFLAGS+=../../libr/fs/p/grub/libgrubfs.a
ifeq ($(HAVE_LIB_GMP),1)
LDFLAGS+=-lgmp
endif
endif

ifeq ($(uname),OpenBSD)
LDFLAGS+=-pthread
endif

ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LDFLAGS+=${SSL_LDFLAGS}
endif
