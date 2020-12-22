/* radare2 - LGPL - Copyright 2016 - Davis, Alex Kornitzer */

#ifndef MDMP_PE_H
#define MDMP_PE_H

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "pe/pe.h"

#include "mdmp_specs.h"

struct PE_(r_bin_mdmp_pe_bin) {
	ut64 vaddr;
	ut64 paddr;
	struct PE_(r_bin_pe_obj_t) *bin;
};


RList *PE_(r_bin_mdmp_pe_get_entrypoint)(struct PE_(r_bin_mdmp_pe_bin) *pe_bin);
RList *PE_(r_bin_mdmp_pe_get_imports)(struct PE_(r_bin_mdmp_pe_bin) *pe_bin);
RList *PE_(r_bin_mdmp_pe_get_sections)(struct PE_(r_bin_mdmp_pe_bin) *pe_bin);
RList *PE_(r_bin_mdmp_pe_get_symbols)(RBin *rbin, struct PE_(r_bin_mdmp_pe_bin) *pe_bin);

#endif /* MDMP_PE_H */
