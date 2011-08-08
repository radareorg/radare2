BIN=ragg2
BINDEPS=r_egg r_bin r_syscall r_asm r_util

include ../binr.mk

ifeq ($(WITHNONPIC),1)
LDFLAGS+=${DL_LIBS}
endif

test:
	./ragg2 -s exithello.r
	./ragg2 -f elf -o a.out exithello.r
	-./a.out ; RET=$$? ; if [ $$RET = 2 ]; then echo It Works ; else echo Oops.. Fail ; fi
