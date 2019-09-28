include ../../libr/config.mk
include ../../mk/platform.mk

CFLAGS+=-I.
LIBMPC=libmpc.${EXT_AR}

OFILES=mpc.o

all: ${LIBMPC}

%.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

${LIBMPC}: $(OFILES)
	rm -f $(LIBMPC)
	$(AR) q $(LIBMPC) $(OFILES)
	$(RANLIB) $(LIBMPC)

clean:
	rm -f $(OBJS) ${LIBMPC} $(OFILES)
