OBJ_PDB=bin_pdb.o
# ../format/pdb/pdb.o ../format/pdb/pdb_downloader.o ../format/pdb/omap.o ../format/pdb/stream_pe.o ../format/pdb/gdata.o
#OBJ_PDB+=../format/pdb/fpo.o ../format/pdb/dbi.o ../format/pdb/tpi.o ../format/pdb/stream_file.o

STATIC_OBJ+=${OBJ_PDB}
TARGET_PDB=bin_pdb.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_PDB}

${TARGET_PDB}: ${OBJ_PDB}
	${CC} $(call libname,bin_pdb) -shared ${CFLAGS} \
		-o ${TARGET_PDB} ${OBJ_PDB} $(LINK) $(LDFLAGS)
endif
