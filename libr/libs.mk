-include libs.custom.mk

ifeq ($(LIBS0),)
LIBS0=util
LIBS1=socket reg cons magic bp config crypto
LIBS2=syscall lang search flag arch esil io
LIBS3=asm fs anal
LIBS4=egg bin
LIBS5=debug
LIBS6=core
LIBS7=core
LIBS8=main

LIBS=$(LIBS0) $(LIBS1) $(LIBS2) $(LIBS3) $(LIBS4) $(LIBS5) $(LIBS6) $(LIBS7) $(LIBS8)
endif

.PHONY: $(LIBS)
