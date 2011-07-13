include ../../libr/config.mk

.PHONY: all clean

CFLAGS+=-I../../libr/include
CFLAGS+=-DLIBDIR=\"${PREFIX}/lib\"

ifeq ($(WITHPIC),1)
LIBS=$(subst r_,-lr_,$(BINDEPS))
LIBS+=$(subst r_,-L../../libr/,$(BINDEPS))
else
PFXDLIBS=$(addsuffix .a,${BINDEPS})
XXXLIBS+=$(subst r_,../../libr/XXX/libr_,$(PFXDLIBS))
LIBS+=$(shell echo ${XXXLIBS} | sed -e 's,XXX/libr_\([^\. ]*\),\1/libr_\1,g')
endif

all: ${BIN}${EXT_EXE}

${BIN}${EXT_EXE}: ${BIN}.o ${OBJS}
	${CC} -o ${BIN}${EXT_EXE} ${OBJS} ${BIN}.o ${LIBS} ${LDFLAGS}

clean: ${MYCLEAN}
	-rm -f ${BIN} ${BIN}.o ${OBJS}

mrproper: clean
	-rm -f ${BIN}.d
