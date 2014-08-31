include ../../config-user.mk
include ../../mk/${COMPILER}.mk

CFLAGS+=-I../../libr/include -fPIC
LDFLAGS+=-L../../libr/util
LIBS=-lr_util
OBJS=transport.o kd.o wind.o iob_pipe.o

all: libr_wind.a

%.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -c $< -o $@

libr_wind.a: $(OBJS)
	rm -f libr_wind.a
	ar rcs libr_wind.a $(OBJS)
	ranlib libr_wind.a

clean:
	rm -f $(OBJS) libr_wind.a 
