include ../../libr/config.mk
include ../../config-user.mk
include ../../mk/platform.mk
include ../../mk/${COMPILER}.mk

CFLAGS:=-I../../libr/include $(CFLAGS)
CFLAGS+=${PIC_CFLAGS}

LIBAR=libr_winkd.${EXT_AR}
LDFLAGS+=-L../../libr/socket -lr_socket
LDFLAGS+=-L../../libr/util -lr_util

include ../../shlr/sdb.mk

OFILES=transport.o kd.o winkd.o iob_pipe.o iob_net.o

all: ${LIBAR}

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

${LIBAR}: $(OFILES)
	rm -f ${LIBAR}
	${AR} q ${LIBAR} ${OFILES}
	${RANLIB} ${LIBAR}

clean:
	rm -f $(OBJS) ${LIBAR} $(OFILES)
