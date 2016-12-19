SPPPATH=../../shlr/spp/
SPP_OBJS=spp.o
SPPOBJS=$(addprefix ${SPPPATH},${SPP_OBJS})
OBJS+=$(SPPOBJS)

$(SPPPATH)/config.h:
	cp -f ${SPPPATH}/config.def.h ${SPPPATH}/config.h
