include ../../config.mk
ifeq ($(WITHPIC),1)
CFLAGS+=-I../../include -I../arch/ -I../arch/include -Wall ${PIC_CFLAGS} ${LDFLAGS_LIB}
CFLAGS+=-DR2__UNIX__

all: ${ALL_TARGETS}

ALL_TARGETS=
#x86.mk arm.mk
#ARCHS=null.mk i4004.mk amd29k.mk
#include $(ARCHS)

clean:
	-rm -f *.so *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d

.PHONY: all clean mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
include ../../../mk/platform.mk
