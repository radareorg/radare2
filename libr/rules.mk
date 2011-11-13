LIBR:=$(abspath $(dir $(lastword $(MAKEFILE_LIST))))
include $(LIBR)/config.mk

#-------------------------------------#
# Rules for libraries
ifneq ($(NAME),)

ALL?=
CFLAGS+=-I../include

all: $(PRE) $(ALL)
	@$(MAKE) real_all

real_all: ${EXTRA_TARGETS} ${LIBSO} ${LIBAR}
	@-if [ -e t/Makefile ]; then (cd t && ${MAKE} all) ; fi
	@-if [ -e p/Makefile ]; then (cd p && ${MAKE} all) ; fi
	@true

SRC=$(subst .o,.c,$(OBJ))

ifeq (${OSTYPE},gnulinux)
LIBNAME=${LDFLAGS_SONAME}${LIBSO}.${LIBVERSION}
else
LIBNAME=${LDFLAGS_SONAME}${LIBSO}
endif

# -j trick
waitfordeps:
	@sh ../waitfordeps.sh ${DEPS}

ifeq ($(WITHPIC),1)
${LIBSO}: $(EXTRA_TARGETS) waitfordeps ${OBJ}
	@for a in ${OBJ} ${SRC}; do \
	  do=0 ; [ ! -e ${LIBSO} ] && do=1 ; \
	  test $$a -nt ${LIBSO} && do=1 ; \
	  if [ $$do = 1 ]; then \
	    echo "${CC_LIB} ${LIBNAME} ${OBJ} ${LDFLAGS} ${LINK}" ; \
	    ${CC_LIB} ${LIBNAME} ${OBJ} ${LDFLAGS} ${LINK}; \
	    if [ -f "../stripsyms.sh" ]; then sh ../stripsyms.sh ${LIBSO} ${NAME} ; fi ; \
	  break ; \
	fi ; done
else
${LIBSO}:
endif

ifeq ($(WITHNONPIC),1)
$(LIBAR): ${OBJ}
	${CC_AR} ${OBJ}
else
$(LIBAR):
endif

MAGICSED=| sed -e 's,-lr_magic,@LIBMAGIC@,g'

pkgcfg:
	@echo Generating pkgconfig stub for ${NAME}
	@echo 'prefix=@PREFIX@' > ../../pkgcfg/${NAME}.pc.acr
	@echo 'exec_prefix=$${prefix}' >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'libdir=@LIBDIR@' >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'includedir=$${prefix}/include' >> ../../pkgcfg/${NAME}.pc.acr
	@echo >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'Name: ${NAME}' >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'Description: radare foundation libraries' >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'Version: @VERSION@' >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'Requires:' >> ../../pkgcfg/${NAME}.pc.acr
	@if [ "${NAME}" = "libr" ]; then NAME=''; else NAME=${NAME}; fi ;\
	echo 'Libs: -L$${libdir} '`echo $${NAME} ${DEPS}|sed -e s,r_,-lr_,g` ${MAGICSED} >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'Cflags: -I$${includedir}/libr' >> ../../pkgcfg/${NAME}.pc.acr

install:
	cd .. && ${MAKE} install

deinstall uninstall:
	cd .. && ${MAKE} uninstall

clean: ${EXTRA_CLEAN}
	-rm -f *.${EXT_EXE} *.${EXT_SO} *.${EXT_AR} *.d
	-rm -f ${LIBSO} ${LIBAR} ${OBJ} ${BIN} *.exe a.out
	-@if [ -e t/Makefile ]; then (cd t && ${MAKE} clean) ; fi
	-@if [ -e p/Makefile ]; then (cd p && ${MAKE} clean) ; fi
	@true

mrproper: clean
	-@if [ -e t/Makefile ]; then (cd t && ${MAKE} mrproper) ; fi
	-@if [ -e p/Makefile ]; then (cd p && ${MAKE} mrproper) ; fi
	-rm -f *.d
	@true

sloc:
	${MAKE} -C ../.. sloc SLOCDIR=libr/$$(echo ${NAME} | sed -e s,r_,,)

.PHONY: all sloc install pkgcfg clean deinstall uninstall

else

#-------------------------------------#
# Rules for programs (including test)

CFLAGS+=-I$(LIBR)/include -DVERSION=\"${VERSION}\"

ifneq ($(BIN),)
all: ${BIN}${EXT_EXE}

${BIN}${EXT_EXE}: ${OBJ}
	${CC} $+ -L.. ${LDFLAGS} ${LDLIBS} -o ${BIN}${EXT_EXE}
endif

# Dummy myclean rule that can be overriden by the t/ Makefile
# TODO: move to config.mk ? it must be a precondition
myclean:

clean: myclean
	-rm -f ${OBJS} ${OBJ} ${BIN}

mrproper: clean
	-rm -f *.d

install:
	cd ../.. && ${MAKE} install

.PHONY: all clean myclean

endif

#-------------------------------

# TODO: deprecate RTDEBUG and R_DEBUG
