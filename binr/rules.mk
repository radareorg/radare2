BINR_PROGRAM=1
include ../../libr/config.mk

CFLAGS+=-DLIBDIR=\"${LIBDIR}\" -I$(LTOP)/include
CFLAGS+=-DR2_BIRTH=\"`date +%Y-%m-%d`\" 
CFLAGS+=-DR2_GITTIP=\"$(GIT_TIP)\"
CFLAGS+=-DR2_GITTAP=\"$(GIT_TAP)\"

ifeq (${COMPILER},emscripten)
EXT_EXE=.js
endif

ifeq ($(USE_RPATH),1)
LDFLAGS+=-Wl,-rpath "${PREFIX}/lib"
endif

OBJ+=${BIN}.o
BEXE=${BIN}${EXT_EXE}

ifeq ($(WITHNONPIC),1)
## LDFLAGS+=$(addsuffix /lib${BINDEPS}.a,$(addprefix ../../libr/,$(subst r_,,$(BINDEPS))))
LDFLAGS+=$(shell for a in ${BINDEPS} ; do b=`echo $$a |sed -e s,r_,,g`; echo ../../libr/$$b/lib$$a.a ; done )
LDFLAGS+=../../shlr/sdb/src/libsdb.a
LDFLAGS+=../../shlr/grub/libgrubfs.a
LDFLAGS+=../../shlr/zip/librz.a
LDFLAGS+=../../shlr/gdb/lib/libgdbr.a
LDFLAGS+=../../shlr/wind/libr_wind.a
LDFLAGS+=../../shlr/capstone/libcapstone.a
LDFLAGS+=../../shlr/java/libr_java.a
ifneq (${OSTYPE},haiku)
LDFLAGS+=-lm
endif
endif
LDFLAGS+=${DL_LIBS}
LDFLAGS+=${LINK}

REAL_LDFLAGS=$(subst -shared,,$(LDFLAGS))

ifeq ($(ISLIB),1)
BEXE=$(BIN).$(EXT_SO)
REAL_LDFLAGS+=-shared
endif
#--------------------#
# Rules for programs #
#--------------------#

# For some reason w32 builds contain -shared in LDFLAGS. boo!

ifneq ($(BIN)$(BINS),)

all: ${BEXE} ${BINS}

${BINS}: ${OBJS}
ifneq ($(SILENT),)
	@echo CC $@
endif
	${CC} ${CFLAGS} $@.c ${OBJS} ${REAL_LDFLAGS} -o $@

${BEXE}: ${OBJ} ${SHARED_OBJ}
ifneq ($(SILENT),)
	@echo LD $@
endif
	${CC} $+ -L.. -o $@ $(REAL_LDFLAGS)
endif

# Dummy myclean rule that can be overriden by the t/ Makefile
# TODO: move to config.mk ? it must be a precondition
myclean:

clean:: myclean
	-rm -f ${OBJS} ${OBJ} ${BEXE}

mrproper: clean
	-rm -f *.d

install:
	cd ../.. && ${MAKE} install

.PHONY: all clean myclean mrproper install
