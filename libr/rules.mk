ifeq ($(_INCLUDE_RULES_MK_),)
_INCLUDE_RULES_MK_=

include $(LTOP)/config.mk

ifeq ($(DEBUG),1)
export NOSTRIP=1
CFLAGS+=-g
LDFLAGS+=-g -ggdb
endif

ALL?=
CFLAGS+=-I$(LIBR)/include
LDFLAGS+=$(addprefix -L../,$(subst r_,,$(BINDEPS)))
LDFLAGS+=$(addprefix -l,$(BINDEPS))
SRC=$(subst .o,.c,$(OBJ))
MAGICSED=| sed -e 's,-lr_magic,@LIBMAGIC@,g'
LIBR:=$(abspath $(dir $(lastword $(MAKEFILE_LIST))))

BEXE=$(BIN)$(EXT_EXE)

ifeq ($(USE_RPATH),1)
LDFLAGS+=-Wl,-R${PREFIX}/lib
endif

ifeq (${OSTYPE},gnulinux)
LIBNAME=${LDFLAGS_SONAME}${LIBSO}.${LIBVERSION}
else
LIBNAME=${LDFLAGS_SONAME}${LIBSO}
endif

all: ${LIBSO} ${LIBAR} ${EXTRA_TARGETS}
ifneq ($(SILENT),)
	@-if [ -f p/Makefile ]; then (cd p && ${MAKE} all) ; fi
else
	@-if [ -f p/Makefile ] ; then (echo "DIR ${NAME}/p"; cd p && ${MAKE} all) ; fi
endif

ifeq ($(WITHPIC),1)
${LIBSO}: $(EXTRA_TARGETS) ${WFD} ${OBJS} ${SHARED_OBJ}
	@for a in ${OBJS} ${SHARED_OBJ} ${SRC}; do \
	  do=0 ; [ ! -e ${LIBSO} ] && do=1 ; \
	  test $$a -nt ${LIBSO} && do=1 ; \
	  if [ $$do = 1 ]; then \
	    [ -n "${SILENT}" ] && \
	    echo "LD $(LIBSO)" || \
	    echo "${CC_LIB} ${LIBNAME} ${OBJS} ${SHARED_OBJ} ${LDFLAGS} ${LINK}" ; \
	    ${CC_LIB} ${LIBNAME} ${OBJS} ${SHARED_OBJ} ${LDFLAGS} ${LINK} || exit 1; \
	    [ -f "$(LIBR)/stripsyms.sh" ] && sh $(LIBR)/stripsyms.sh ${LIBSO} ${NAME} ; \
	  break ; \
	fi ; done
else
${LIBSO}: ;
endif

ifeq ($(WITHNONPIC),1)
$(LIBAR): ${OBJS}
ifneq ($(SILENT),)
	echo "CC_AR $(LIBAR)"
endif
	${CC_AR} ${OBJS} ${SHARED_OBJ}
else
$(LIBAR): ;
endif

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

clean:: ${EXTRA_CLEAN}
	-rm -f *.${EXT_EXE} *.${EXT_SO} *.${EXT_AR} *.d */*.d */*/*.d */*/*/*.d
	-rm -f ${LIBSO} ${LIBAR} ${OBJS} ${BIN} *.exe a.out
	-@if [ -e p/Makefile ]; then (cd p && ${MAKE} clean) ; fi
	@true

mrproper: clean
	-@if [ -e p/Makefile ]; then (cd p && ${MAKE} mrproper) ; fi
	-rm -f *.d
	@true

.PHONY: all install pkgcfg clean deinstall uninstall echodir

# autodetect dependencies object
-include $(OBJS:.o=.d)

endif
