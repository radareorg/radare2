#ifndef MDMP_PE_H
#define MDMP_PE_H

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "pe/pe.h"

#include "mdmp_specs.h"

typedef struct PE_(r_bin_mdmp_pe_bin) {
	ut64 vaddr;
	ut64 paddr;
	struct PE_(r_bin_pe_obj_t) *bin;
} PE_(RBinMdmp);

RList *PE_(r_bin_mdmp_pe_get_entrypoint)(PE_(RBinMdmp) *mdmp);
RList *PE_(r_bin_mdmp_pe_get_imports)(PE_(RBinMdmp) *mdmp);
RList *PE_(r_bin_mdmp_pe_get_sections)(PE_(RBinMdmp) *mdmp);
RList *PE_(r_bin_mdmp_pe_get_symbols)(RBin *rbin, PE_(RBinMdmp) *mdmp);

#endif /* MDMP_PE_H */
