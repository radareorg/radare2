-include libs.custom.mk

ifeq ($(LIBS0),)
LIBS0=util
LIBS1=socket reg cons bp config crypto syscall
LIBS2=search flag esil
LIBS3=arch io # esil depends on reg and esil
LIBS4=asm anal magic fs
LIBS5=lang egg bin
LIBS6=debug
LIBS7=core
LIBS8=main

LIBS=$(LIBS0) $(LIBS1) $(LIBS2) $(LIBS3) $(LIBS4) $(LIBS5) $(LIBS6) $(LIBS7) $(LIBS8)
endif

.PHONY: $(LIBS)
