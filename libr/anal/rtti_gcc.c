/* radare - LGPL - Copyright 2009-2018 - pancake, maijin, r00tus3r */

#include <r_anal.h>
#include "r_anal.h"

struct type_info;
struct class_type_info;
struct si_class_type_info;
struct vmi_class_type_info;
struct base_class_type_info;

static void rtti_gcc_print_complete_object_locator_recurse(RVTableContext *context, ut64 atAddress) {
  eprintf ("Work in Progress. RTTI not yet supported for Itanium. \n");
}

R_API void r_anal_rtti_gcc_print_at_vtable(RVTableContext *context, ut64 addr, int mode) {
	rtti_gcc_print_complete_object_locator_recurse (context, addr);
}
