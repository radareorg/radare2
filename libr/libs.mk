-include libs.custom.mk

ifeq ($(LIBS0),)
LIBS0=util
LIBS1=socket reg cons magic bp config
LIBS2=syscall lang crypto flag arch esil
LIBS3=parse io search
LIBS4=asm fs anal
LIBS5=egg bin
LIBS6=debug
LIBS7=core
LIBS8=main

LIBS=$(LIBS0) $(LIBS1) $(LIBS2) $(LIBS3) $(LIBS4) $(LIBS5) $(LIBS6) $(LIBS7) $(LIBS8)
endif

.PHONY: $(LIBS)
