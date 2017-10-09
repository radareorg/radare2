SPPPATH=../../shlr/spp/
CFLAGS+=-DHAVE_FORK=$(HAVE_FORK)
SPP_OBJS=spp.o
SPPOBJS=$(addprefix ${SPPPATH},${SPP_OBJS})
OBJS+=$(SPPOBJS)

$(SPPPATH)/config.h: $(SPPPATH)/config.def.h
	$(MAKE) spp_config

spp_config:
	cp -f $(SPPPATH)/config.def.h $(SPPPATH)/config.h
	$(MAKE) spp_build

spp_build: $(SPPOBJS)
