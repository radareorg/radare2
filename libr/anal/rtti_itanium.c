/* radare - LGPL - Copyright 2009-2018 - pancake, maijin, r00tus3r */

#include <r_anal.h>
#include "r_anal.h"

typedef struct type_info_t {
        ut32 vtable_addr;
        ut32 name_addr;
} type_info;

typedef struct class_type_info_t {
        ut32 vtable_addr;
        ut32 name_addr;
} class_type_info;

typedef struct base_class_type_info_t {
        ut32 base_class_addr;
        ut32 offset_flags;
        enum offset_flags_masks_e {
                base_is_virtual = 0x1,
                base_is_public = 0x2
        } offset_flags_masks;
} base_class_type_info;

typedef struct si_class_type_info_t {
        ut32 vtable_addr;
        ut32 name_addr;
        ut32 base_class_addr;
} si_class_type_info;

typedef struct vmi_class_type_info_t {
        ut32 vtable_addr;
        ut32 name_addr;
        int vmi_flags;
        int vmi_base_count;
        base_class_type_info vmi_bases[1];
        enum vmi_flags_masks_e {
                non_diamond_repeat_mask = 0x1,
                diamond_shaped_mask = 0x2,
                non_public_base_mask = 0x4,
                public_base_mask = 0x8
        }vmi_flags_masks;
} vmi_class_type_info;

static bool rtti_itanium_read_class_type_info (RVTableContext *context, ut64 addr, class_type_info *col) {
        if (addr == UT64_MAX) {
                return false;
        }
        return true;
}

static void rtti_itanium_print_class_type_info (class_type_info *col, ut64 addr, const char *prefix) {
        r_cons_printf ("%sType Info at 0x%08"PFMT64x ":\nWork in Progress.\n",
				   prefix, addr);
}

R_API void r_anal_rtti_itanium_print_class_type_info(RVTableContext *context, ut64 addr, int mode) {
	class_type_info col;
	if (!rtti_itanium_read_class_type_info (context, addr, &col)) {
		eprintf ("Failed to parse Type Info at 0x%08"PFMT64x"\n", addr);
		return;
	}
	rtti_itanium_print_class_type_info (&col, addr, "");
}

static void rtti_itanium_print_class_type_info_recurse(RVTableContext *context, ut64 atAddress) {
        ut64 colRefAddr = atAddress - context->word_size; //Vtable: Type Info
        ut64 colAddr;//Type Info

        if (!context->read_addr (context->anal, colRefAddr, &colAddr)) {
                return;
        }

        class_type_info col;
        if (!rtti_itanium_read_class_type_info (context, colAddr, &col)) {
                eprintf ("Failed to parse Type Info at 0x%08"PFMT64x" (referenced from 0x%08"PFMT64x")\n", colAddr, colRefAddr);
                return;
        }
        rtti_itanium_print_class_type_info (&col, colAddr, "");
}

R_API void r_anal_rtti_itanium_print_at_vtable(RVTableContext *context, ut64 addr, int mode) {
        rtti_itanium_print_class_type_info_recurse (context, addr);
}
