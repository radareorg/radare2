#ifndef PSXEXE_H
#define PSXEXE_H

#define PSXEXE_ID "PS-X EXE"
#define PSXEXE_ID_LEN 8
#define PSXEXE_TEXTSECTION_OFFSET 0x800

#include <r_types.h>

typedef struct psxexe_header {
	ut8 id[8];
	ut32 text;
	ut32 data;
	ut32 pc0;
	ut32 gp0;
	ut32 t_addr;
	ut32 t_size;
	ut32 d_addr;
	ut32 d_size;
	ut32 b_addr;
	ut32 b_size;
	ut32 S_addr;
	ut32 S_size;
	ut32 SavedSP;
	ut32 SavedFP;
	ut32 SavedGP;
	ut32 SavedRA;
	ut32 SavedS0;
} psxexe_header;

#endif // PSXEXE_H
