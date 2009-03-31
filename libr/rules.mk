CFLAGS+=-DUSE_RIO=${USE_RIO}
CFLAGS+=${CFLAGS_APPEND}
LDFLAGS+=$(subst r_,-lr_,$(DEPS))
LDFLAGS+=$(subst r_,-L../,$(DEPS))

LDFLAGS+=$(subst r_,-lr_,$(BINDEPS))
LDFLAGS+=$(subst r_,-L../../,$(BINDEPS))
BOO=-Wl,-R../../
LDFLAGS+=$(subst r_,${BOO},$(BINDEPS))

# Compiler
#CC?=gcc
#CFLAGS+=-fPIC
#CC_LIB=${CC} -shared -o ${LIBSO}
#CC_AR=ar -r ${LIBAR}
#LINK?=

# Debug
CFLAGS+=-g -Wall

# XXX hardcoded XXX #
OSTYPE=gnulinux
# Output
ifeq (${OSTYPE},windows)
EXT_AR=lib
EXT_SO=dll
endif
ifeq (${OSTYPE},gnulinux)
EXT_AR=a
EXT_SO=so
endif
ifeq (${OSTYPE},osx)
EXT_AR=a
EXT_SO=dylib
endif

LIB=lib${NAME}
LIBAR=${LIB}.${EXT_AR}
LIBSO=${LIB}.${EXT_SO}

#-------------------------------------#
# Rules
ifeq (${BINDEPS},)
ifneq ($(NAME),)
include ../../config.mk
include ../../mk/${COMPILER}.mk

CFLAGS+=-I../include
real_all all: ${LIBSO} ${EXTRA_TARGETS}
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

clean: ${EXTRA_CLEAN}
	-rm -f ${LIBSO} ${LIBAR} ${OBJ} ${BIN} *.so a.out *.a *.exe
	@if [ -e t/Makefile ]; then (cd t && ${MAKE} clean) ; fi
	@if [ -e p/Makefile ]; then (cd p && ${MAKE} clean) ; fi
	@true
.PHONY: all clean ${LIBSO} ${LIBAR}
endif
else

include ../../config.mk
include ../../../mk/${COMPILER}.mk
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

#-------------------------------

#if RUNTIME_DEBUG
CFLAGS+=-DR_RTDEBUG
#endif

#if STATIC_DEBUG
CFLAGS+=-DR_DEBUG
#endif

