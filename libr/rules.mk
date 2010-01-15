-include config.mk
-include ../config.mk
-include ../../config.mk
-include global.mk
-include ../global.mk
-include ../../global.mk
#-include ../../../config.mk

#-------------------------------------#
# Rules for libraries
ifeq (${BINDEPS},)

ifneq ($(NAME),)
#include ../../config-user.mk
#include ../../mk/${COMPILER}.mk

CFLAGS+=-I../include
real_all all: ${LIBSO} ${LIBAR} ${EXTRA_TARGETS}
	@-if [ -e t/Makefile ]; then (cd t && ${MAKE} all) ; fi
	@-if [ -e p/Makefile ]; then (cd p && ${MAKE} all) ; fi
	@true

SRC=$(subst .o,.c,$(OBJ))

${LIBSO}: ${OBJ}
	@for a in ${OBJ} ${SRC}; do \
	  do=0 ; [ ! -e ${LIBSO} ] && do=1 ; \
	  test $$a -nt ${LIBSO} && do=1 ; \
	  if [ $$do = 1 ]; then \
	    echo "${CC_LIB} ${LDFLAGS} ${LINK} ${OBJ}" ; \
	    ${CC_LIB} ${LDFLAGS} ${LINK} ${OBJ} ; \
	    if [ -f "../stripsyms.sh" ]; then sh ../stripsyms.sh ${LIBSO} ${NAME} ; fi ; \
	  break ; \
	fi ; done

${LIBAR}: ${OBJ}
	${CC_AR} ${OBJ}

pkgcfg:
	@echo Generating pkgconfig stub for ${NAME}
	@echo 'prefix=@PREFIX@' > ../../pkgcfg/${NAME}.pc.acr
	@echo 'exec_prefix=$${prefix}' >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'libdir=$${exec_prefix}/lib' >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'includedir=$${prefix}/include' >> ../../pkgcfg/${NAME}.pc.acr
	@echo >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'Name: ${NAME}' >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'Description: radare foundation libraries' >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'Version: ${VERSION}' >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'Requires:' >> ../../pkgcfg/${NAME}.pc.acr
	@if [ "${NAME}" = "libr" ]; then NAME=''; else NAME=${NAME}; fi ;\
	echo 'Libs: -L$${libdir} '`echo $${NAME} ${DEPS}|sed -e s,r_,-lr_,g` >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'Cflags: -I$${includedir}/libr' >> ../../pkgcfg/${NAME}.pc.acr

install:
	cd .. && ${MAKE} install

deinstall uninstall:
	cd .. && ${MAKE} uninstall

clean: ${EXTRA_CLEAN}
	-rm -f *.${EXT_EXE} *.${EXT_SO} *.${EXT_AR}
	-rm -f ${LIBSO} ${LIBAR} ${OBJ} ${BIN} *.exe a.out
	@if [ -e t/Makefile ]; then (cd t && ${MAKE} clean) ; fi
	@if [ -e p/Makefile ]; then (cd p && ${MAKE} clean) ; fi
	@true

sloc:
	${MAKE} -C ../.. sloc SLOCDIR=libr/$$(echo ${NAME} | sed -e s,r_,,)

.PHONY: all sloc install pkgcfg clean deinstall uninstall

else

# somewhere else?

endif


else

#-------------------------------------#
# Rules for test programs

include ../../../config-user.mk
include ../../../mk/${COMPILER}.mk

CFLAGS+=-I../../include -DVERSION=\"${VERSION}\"

ifneq ($(BIN),)
all: ${BIN}${EXT_EXE}

${BIN}${EXT_EXE}: ${OBJ}
	@echo BIN=${BIN}
	${CC} ${LDFLAGS} ${LIBS} ${OBJ} -o ${BIN}${EXT_EXE}
endif

#Dummy myclean rule that can be overriden by the t/ Makefile
myclean:

clean: myclean
	-rm -f ${OBJ} ${BIN}

.PHONY: all clean myclean

endif

#-------------------------------

#if RUNTIME_DEBUG
CFLAGS+=-DR_RTDEBUG
#endif

// TODO: Not working
#if STATIC_DEBUG
#CFLAGS+=-DR_DEBUG
#endif
