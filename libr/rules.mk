ifeq ($(_INCLUDE_RULES_MK_),)
_INCLUDE_RULES_MK_=

-include $(LTOP)/config.mk
-include $(LTOP)/../mk/compiler.mk

WITH_LIBS?=1

ifeq ($(DEBUG),1)
export NOSTRIP=1
CFLAGS+=-g
LINK+=-g
endif

LIBR:=$(abspath $(dir $(lastword $(MAKEFILE_LIST))))
# /libr

ALL?=
CFLAGS+=-I$(LIBR)
CFLAGS+=-I$(LIBR)/include

-include $(SHLR)/sdb.mk

CFLAGS+=-fvisibility=hidden
LDFLAGS+=-fvisibility=hidden
LINK+=-fvisibility=hidden

# for executables (DUP)
LINK+=$(addprefix -L../,$(subst r_,,$(BINDEPS)))
LINK+=$(addprefix -l,$(BINDEPS))

SRC=$(subst .o,.c,$(OBJ))

BEXE=$(BIN)$(EXT_EXE)

ifeq ($(USE_RPATH),1)
LINK+=-Wl,-rpath "${LIBDIR}"
endif

ifeq (${OSTYPE},gnulinux)
ifeq (${HAVE_LIBVERSION},1)
LIBNAME=${LDFLAGS_SONAME}${LIBSO}.${LIBVERSION}
else
LIBNAME=${LDFLAGS_SONAME}${LIBSO}
endif
else
ifeq (${OSTYPE},darwin)
ifeq (${HAVE_LIBVERSION},1)
LIBNAME=${LDFLAGS_SONAME}${LIB}.${LIBVERSION}.${EXT_SO}
else
LIBNAME=${LDFLAGS_SONAME}${LIB}.${EXT_SO}
endif
else
LIBNAME=${LDFLAGS_SONAME}${LIBSO}
endif
endif

ifeq (${OSTYPE},haiku)
LINK+=-lnetwork
endif

ifeq (${OSTYPE},solaris)
LINK+=-lproc
endif

ifneq ($(EXTRA_PRE),)
all: $(EXTRA_PRE)
	$(MAKE) all2

all2: ${LIBSO} ${LIBAR} ${EXTRA_TARGETS}
else
all: ${LIBSO} ${LIBAR} ${EXTRA_TARGETS}
endif
ifneq ($(SILENT),)
	@-if [ -f p/Makefile ]; then (cd p && ${MAKE}) ; fi
else
	@-if [ -f p/Makefile ] ; then (echo "DIR ${NAME}/p"; cd p && ${MAKE}) ; fi
endif

ifeq ($(WITH_LIBS),1)
$(LIBSO): $(EXTRA_TARGETS) ${WFD} ${OBJS} ${SHARED_OBJ}
	@for a in ${OBJS} ${SHARED_OBJ} ${SRC}; do \
	  do=0 ; [ ! -e "${LIBSO}" ] && do=1 ; \
	  test "$$a" -nt "${LIBSO}" && do=1 ; \
	  if [ $$do = 1 ]; then \
	    [ -n "${SILENT}" ] && \
	    echo "LD $(LIBSO)" || \
	    echo "\"${CC_LIB} ${LIBNAME} ${OBJS} ${SHARED_OBJ} ${LINK} ${LDFLAGS}\"" ; \
	    ${CC_LIB} ${LIBNAME} ${CFLAGS} ${OBJS} ${SHARED_OBJ} ${LINK} ${LDFLAGS} || exit 1; \
	    [ -f "$(LIBR)/stripsyms.sh" ] && sh "$(LIBR)/stripsyms.sh" "${LIBSO}" ${NAME} ; \
	  break ; \
	fi ; done
else
$(LIBSO): ;
endif

ifeq ($(WITH_LIBR),1)
$(LIBAR): ${OBJS}
	@[ "${SILENT}" = 1 ] && echo "CC_AR $(LIBAR)" || true
	rm -f $(LIBAR)
	${CC_AR} ${OBJS} ${SHARED_OBJ}
	${RANLIB} $(LIBAR)
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
	@echo 'Requires: $(filter r_%,${R2DEPS})' >> ../../pkgcfg/${NAME}.pc.acr
	@if [ "${NAME}" = "libr" ]; then NAME=''; else NAME=${NAME}; fi ;\
	echo 'Libs: -L$${libdir} -l${NAME} $(filter-out r_%,${R2DEPS}) ${PCLIBS}' >> ../../pkgcfg/${NAME}.pc.acr
	@echo 'Cflags: -I$${includedir}/libr ${PCCFLAGS}' >> ../../pkgcfg/${NAME}.pc.acr

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
