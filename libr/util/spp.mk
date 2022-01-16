SPPPATH=../../shlr/spp/
CFLAGS+=-DHAVE_FORK=$(HAVE_FORK) -DUSE_R2=1
CFLAGS+=-I../../shlr
SPP_OBJS=spp.o
SPPOBJS=$(addprefix ${SPPPATH},${SPP_OBJS})
OBJS+=$(SPPOBJS)

$(SPPPATH)/config.h: $(SPPPATH)/config.def.h
	$(MAKE) spp_config

spp_config:
	cmp $(SPPPATH)/config.def.h $(SPPPATH)/config.h 2> /dev/null || \
		cp -f $(SPPPATH)/config.def.h $(SPPPATH)/config.h
	$(MAKE) spp_build

spp_build: $(SPPOBJS)
