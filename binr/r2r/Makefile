BIN=r2r
BINDEPS=r_util r_cons
OBJ=load.o run.o
#CFLAGS+=-DALLINC=1

include ../rules.mk

# Ensure top-level libr.a has an archive index before linking
PRELINK = ../../libr/libr.a
$(PRELINK):
	$(RANLIB) $(PRELINK) || true

# Ensure libr.a has an index before linking
$(TOP)/libr/libr.a:
	$(RANLIB) $(TOP)/libr/libr.a || true
include ../../libr/util/deps.mk

LDFLAGS+=${DL_LIBS}
LDFLAGS+=$(CLOCK_LDFLAGS)
LDFLAGS+=$(LINK)
