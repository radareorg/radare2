#ifndef LE_H
#define LE_H

#include <r_bin.h>
#include "le_specs.h"

typedef struct r_bin_le_obj_s {
	LE_image_header *header;
	bool is_le; /* Used for differences between LE and LX */
	char *filename;
	const char *type;
	const char *cpu;
	const char *os;
	const char *arch;
	ut32 headerOff; /* File offset to start of LE/LX header */
	LE_object_entry *objtbl;
	void *buf; /* Pointer to RBuffer of file */
	ut64 *obj_bases;
	size_t n_bases;
} RBinLEObj;

R_IPI RBinLEObj *r_bin_le_new_buf(RBuffer *buf);
R_IPI void r_bin_le_free(RBinLEObj *bin);
R_IPI RList *r_bin_le_get_entrypoints(RBinLEObj *bin);
R_IPI RList *r_bin_le_get_sections(RBinLEObj *bin);
R_IPI RList *r_bin_le_get_symbols(RBinLEObj *bin);
R_IPI RList *r_bin_le_get_imports(RBinLEObj *bin);
R_IPI RList *r_bin_le_get_libs(RBinLEObj *bin);
R_IPI RList *r_bin_le_get_relocs(RBinLEObj *bin);
#endif
