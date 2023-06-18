OBJ_PCAP=bin_pcap.o ../format/pcap/pcap.o

STATIC_OBJ+=${OBJ_PCAP}
TARGET_PCAP=bin_pcap.${LIBEXT}
CFLAGS+=-I../format/pcap/

ALL_TARGETS+=${TARGET_PCAP}

${TARGET_PCAP}: ${OBJ_PCAP}
	${CC} ${CFLAGS} -o ${TARGET_PCAP} ${OBJ_PCAP} $(R2_CFLAGS) $(R2_LDFLAGS) -lr_util
