CFLAGS+=-DUSE_RIO=${USE_RIO}
CFLAGS+=${CFLAGS_APPEND}
LDFLAGS+=$(subst r_,-lr_,$(DEPS))
LDFLAGS+=$(subst r_,-L../,$(DEPS))

LDFLAGS+=$(subst r_,-lr_,$(BINDEPS))
LDFLAGS+=$(subst r_,-L../../,$(BINDEPS))
BOO=-Wl,-R../../
LDFLAGS+=$(subst r_,${BOO},$(BINDEPS))

# Compiler
CC?=gcc
CFLAGS+=-fPIC
CC_LIB=${CC} -shared -o ${LIBSO}
CC_AR=ar -r ${LIBAR}
LINK?=

# Debug
CFLAGS+=-g -Wall

# Output
EXT_AR=a
EXT_SO=so
LIB=lib${NAME}
LIBAR=${LIB}.${EXT_AR}
LIBSO=${LIB}.${EXT_SO}
# ${LIBAR}
# Rules
ifeq (${BINDEPS},)
ifneq ($(NAME),)
include ../config.mk
CFLAGS+=-I../include
all: ${LIBSO}
	@-if [ -e t/Makefile ]; then (cd t && ${MAKE} all) ; fi
	@-if [ -e p/Makefile ]; then (cd p && ${MAKE} all) ; fi
	@true

${LIBSO}: ${OBJ}
	${CC_LIB} ${LDFLAGS} ${LINK} ${OBJ}
	@if [ -f "../stripsyms.sh" ]; then sh ../stripsyms.sh ${LIBSO} ${NAME} ; fi

${LIBAR}: ${OBJ}
	${CC_AR} ${OBJ}

install:
	cd .. && ${MAKE} install

clean:
	-rm -f ${LIBSO} ${LIBAR} ${OBJ} ${BIN} *.so a.out *.a *.exe
	@if [ -e t/Makefile ]; then (cd t && ${MAKE} clean) ; fi
	@if [ -e p/Makefile ]; then (cd p && ${MAKE} clean) ; fi
	@true
.PHONY: all clean ${LIBSO} ${LIBAR}
endif
else
include ../../config.mk
CFLAGS+=-I../../include
all: ${BIN}
	@true

${BIN}: ${OBJ}
	${CC} ${LDFLAGS} ${OBJ} -o ${BIN} ${LIBS}

#Dummy myclean rule that can be overriden by the t/ Makefile
myclean:

clean: myclean
	-rm -f ${OBJ} ${BIN}

.PHONY: all clean ${BIN}
endif
