include ../../global.mk
include $(TOP)/libr/config.mk

PYTHON=python2
SRC=$(shell ls *.c)
OUT=$(subst .c,.o,$(SRC))
CFLAGS+=-DHAVE_STRING_H=1

all: $(OUT)

$(OUT):
	$(CC) $(CFLAGS) $(LDFLAGS) -c `echo $@|sed -e 's,\.o,\.c,g'`

sync:
	rm -rf tmp
	mkdir -p tmp
	git clone git://github.com/radare/udis86.git
	cd udis86/libudis86 ; ${PYTHON} ../scripts/ud_itab.py ../docs/x86/optable.xml .
	cp -f udis86/libudis86/*.[ch] .
	rm -rf udis86

clean mrproper:
	rm -f *.o *.d
