-include libs.custom.mk

ifeq ($(LIBS0),)
LIBS0=util
LIBS1=socket reg cons magic bp config crypto syscall
LIBS2=search flag arch esil io
LIBS3=asm fs anal
LIBS4=lang bin
LIBS5=debug egg
LIBS6=core
LIBS7=main
LIBS8=

LIBS=$(LIBS0) $(LIBS1) $(LIBS2) $(LIBS3) $(LIBS4) $(LIBS5) $(LIBS6) $(LIBS7) $(LIBS8)
endif

.PHONY: $(LIBS)
