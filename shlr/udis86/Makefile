include ../../global.mk
include $(TOP)/libr/config.mk

SRC=$(shell ls *.c)
OUT=$(subst .c,.o,$(SRC))

all: $(OUT)

$(OUT):
	$(CC) $(CFLAGS) $(LDFLAGS) -c `echo $@|sed -e 's,\.o,\.c,g'`

clean mrproper:
	rm -f *.o *.d
