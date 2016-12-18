SPPPATH=../../shlr/spp/
SPP_OBJS=spp.o
SPPOBJS=$(addprefix ${SPPPATH},${SPP_OBJS})
OBJS+=$(SPPOBJS)

$(shell cp ${SPPPATH}/config.def.h ${SPPPATH}/config.h)
