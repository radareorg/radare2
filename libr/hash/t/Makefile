include ../../config.mk

# already appended in rules.mk ${EXT_EXE}
BINDEPS=r_io r_hash r_util r_socket
LIBS=-lm
ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LDFLAGS+=${SSL_LDFLAGS}
endif

all: hello${EXT_EXE}

hello${EXT_EXE}: hello.o
	@#${CC} -I../../include hello.o -Wl,-R.. -L.. -L../../io -L../../util -L../../lib -lr_util -lr_lib -lr_hash -lr_io -o hello
	${CC} hello.o ${CFLAGS} ${LDFLAGS} -o hello${EXT_EXE}

myclean:
	rm -f hello${EXT_EXE} hello.o ${BIN}

include ../../rules.mk
