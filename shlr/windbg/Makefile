include ../../libr/config.mk
include ../../config-user.mk
include ../../mk/platform.mk
include ../../mk/${COMPILER}.mk

CFLAGS+=${PIC_CFLAGS}

CFLAGS+=-I../../libr/include
LIBAR=libr_windbg.${EXT_AR}
LDFLAGS+=-L../../libr/util
LIBS=-lr_util

OFILES=transport.o kd.o windbg.o iob_pipe.o

all: ${LIBAR}

%.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

${LIBAR}: $(OFILES)
	rm -f ${LIBAR}
	${AR} q ${LIBAR} ${OFILES}
	${RANLIB} ${LIBAR}

clean:
	rm -f $(OBJS) ${LIBAR} $(OFILES)
