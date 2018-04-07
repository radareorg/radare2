/* radare - LGPL - Copyright 2018 - pancake, r00tus3r */

#include <r_anal.h>
#include <r_core.h>
#include <r_flag.h>
#include <r_cons.h>

#define vmi_class_type_info_name "obj.vtablefor__cxxabiv1::__vmi_class_type_info"
#define class_type_info_name "obj.vtablefor__cxxabiv1::__class_type_info"
#define si_class_type_info_name "obj.vtablefor__cxxabiv1::__si_class_type_info"

typedef struct class_type_info_t {
        ut32 vtable_addr;
        ut32 name_addr;
} class_type_info;

typedef struct base_class_type_info_t {
        ut32 base_class_addr;
        ut32 flags;
        enum flags_masks_e {
                base_is_virtual = 0x1,
                base_is_public = 0x2
        } flags_masks;
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
        base_class_type_info *vmi_bases;
        enum vmi_flags_masks_e {
                non_diamond_repeat_mask = 0x1,
                diamond_shaped_mask = 0x2,
                non_public_base_mask = 0x4,
                public_base_mask = 0x8
        } vmi_flags_masks;
} vmi_class_type_info;

static bool rtti_itanium_read_class_type_info (RVTableContext *context, ut64 addr, class_type_info *cti) {
        if (addr == UT64_MAX) {
                return false;
        }
        if (!context->read_addr (context->anal, addr, &cti->vtable_addr)) {
                return false;
        }
        if (!context->read_addr (context->anal, addr + context->word_size, &cti->name_addr)) {
                return false;
        }
        return true;
}

static bool rtti_itanium_read_vmi_class_type_info (RVTableContext *context, ut64 addr, vmi_class_type_info *vmi_cti) {
        if (addr == UT64_MAX) {
                return false;
        }
        if (!context->read_addr (context->anal, addr, &vmi_cti->vtable_addr)) {
                return false;
        }

        addr += context->word_size;
        if (!context->read_addr (context->anal, addr, &vmi_cti->name_addr)) {
                return false;
        }

        addr += context->word_size;
        if (!context->read_addr (context->anal, addr, &vmi_cti->vmi_flags)) {
                return false;
        }

        addr += 0x4;
        if (!context->read_addr (context->anal, addr, &vmi_cti->vmi_base_count)) {
                return false;
        }

        vmi_cti->vmi_bases = malloc (sizeof (base_class_type_info) * vmi_cti->vmi_base_count);
        ut64 tmp_addr = addr + 0x4;

        int i;
        for(i = 0; i < vmi_cti->vmi_base_count; i++) {
                if (!context->read_addr (context->anal, tmp_addr, &vmi_cti->vmi_bases[i].base_class_addr)) {
                        return false;
                }
                tmp_addr += context->word_size;
                if (!context->read_addr (context->anal, tmp_addr, &vmi_cti->vmi_bases[i].flags)) {
                        return false;
                }
                tmp_addr += context->word_size;
        }
        return true;
}

static bool rtti_itanium_read_si_class_type_info (RVTableContext *context, ut64 addr, si_class_type_info *si_cti) {
        if (addr == UT64_MAX) {
                return false;
        }
        if (!context->read_addr (context->anal, addr, &si_cti->vtable_addr)) {
                return false;
        }
        if (!context->read_addr (context->anal, addr + context->word_size, &si_cti->name_addr)) {
                return false;
        }
        if (!context->read_addr (context->anal, addr + 2 * context->word_size, &si_cti->base_class_addr)) {
                return false;
        }
        return true;
}

static void rtti_itanium_print_class_type_info (class_type_info *cti, ut64 addr, const char *prefix) {
        r_cons_printf ("%sType Info at 0x%08"PFMT64x ":\n"
                                "%s  Reference to RTTI's type class: 0x%08"PFMT32x "\n"
                                "%s  Reference to type's name: 0x%08"PFMT32x "\n",
				prefix, addr,
                                prefix, cti->vtable_addr,
                                prefix, cti->name_addr);
}

static void rtti_itanium_print_vmi_class_type_info (vmi_class_type_info *vmi_cti, ut64 addr, const char *prefix) {
        r_cons_printf ("%sType Info at 0x%08"PFMT64x ":\n"
                                "%s  Reference to RTTI's type class: 0x%08"PFMT32x "\n"
                                "%s  Reference to type's name: 0x%08"PFMT32x "\n"
                                "%s  Flags: 0x%x" "\n"
                                "%s  Count of base classes: 0x%x" "\n",
				prefix, addr,
                                prefix, vmi_cti->vtable_addr,
                                prefix, vmi_cti->name_addr,
                                prefix, vmi_cti->vmi_flags,
                                prefix, vmi_cti->vmi_base_count);

        int i;
        for (i = 0; i < vmi_cti->vmi_base_count; i++) {
                r_cons_printf("%s      Base class type descriptor address: 0x%08"PFMT32x "\n"
                                        "%s      Base class flags: 0x%x" "\n",
                                        prefix, vmi_cti->vmi_bases[i].base_class_addr,
                                        prefix, vmi_cti->vmi_bases[i].flags);
        }
}

static void rtti_itanium_print_si_class_type_info (si_class_type_info *si_cti, ut64 addr, const char *prefix) {
        r_cons_printf ("%sType Info at 0x%08"PFMT64x ":\n"
                                "%s  Reference to RTTI's type class: 0x%08"PFMT32x "\n"
                                "%s  Reference to type's name: 0x%08"PFMT32x "\n"
                                "%s  Reference to parent's type name: 0x%08"PFMT32x "\n",
                                prefix, addr,
                                prefix, si_cti->vtable_addr,
                                prefix, si_cti->name_addr,
                                prefix, si_cti->base_class_addr);
}

R_API void r_anal_rtti_itanium_print_class_type_info(RVTableContext *context, ut64 addr, int mode) {
        class_type_info cti;
        if (!rtti_itanium_read_class_type_info (context, addr, &cti)) {
                eprintf ("Failed to parse Type Info at 0x%08"PFMT64x"\n", addr);
                return;
        }
        rtti_itanium_print_class_type_info (&cti, addr, "");
}

R_API void r_anal_rtti_itanium_print_si_class_type_info(RVTableContext *context, ut64 addr, int mode) {
        si_class_type_info si_cti;
        if (!rtti_itanium_read_si_class_type_info (context, addr, &si_cti)) {
                eprintf ("Failed to parse Type Info at 0x%08"PFMT64x"\n", addr);
                return;
        }
        rtti_itanium_print_si_class_type_info (&si_cti, addr, "");
}

R_API void r_anal_rtti_itanium_print_vmi_class_type_info(RVTableContext *context, ut64 addr, int mode) {
        vmi_class_type_info vmi_cti;
        if (!rtti_itanium_read_vmi_class_type_info (context, addr, &vmi_cti)) {
                eprintf ("Failed to parse Type Info at 0x%08"PFMT64x"\n", addr);
                return;
        }
        rtti_itanium_print_vmi_class_type_info (&vmi_cti, addr, "");
}

static bool rtti_itanium_print_class_type_info_recurse(RVTableContext *context, ut64 atAddress) {
        ut64 colRefAddr = atAddress - context->word_size; //Vtable: Type Info
        ut64 colAddr; //Type Info
        ut64 class_type_offset;

        if (!context->read_addr (context->anal, colRefAddr, &colAddr)) {
                return false;
        }

        if (!context->read_addr (context->anal, colAddr, &class_type_offset)) {
                return false;
        }

        RCore *core = context->anal->coreb.core;

    	if (!core) {
    		return false;
    	}

        class_type_offset -= 2 * context->word_size;
        RFlagItem *flag;

        flag = r_flag_get_i(core->flags, class_type_offset);
        if (!flag) {
                eprintf ("No RTTI found\n");
                return false;
        }

        if (r_str_cmp (flag->name, vmi_class_type_info_name, r_str_len_utf8 (flag->name))) {
                vmi_class_type_info vmi_cti;
                if (!rtti_itanium_read_vmi_class_type_info (context, colAddr, &vmi_cti)) {
                        eprintf ("Failed to parse Type Info at 0x%08"PFMT64x" (referenced from 0x%08"PFMT64x")\n", colAddr, colRefAddr);
                        return false;
                }
                rtti_itanium_print_vmi_class_type_info (&vmi_cti, colAddr, "");
        }

        if (r_str_cmp (flag->name, si_class_type_info_name, r_str_len_utf8 (flag->name))) {
                si_class_type_info si_cti;
                if (!rtti_itanium_read_si_class_type_info (context, colAddr, &si_cti)) {
                        eprintf ("Failed to parse Type Info at 0x%08"PFMT64x" (referenced from 0x%08"PFMT64x")\n", colAddr, colRefAddr);
                        return false;
                }
                rtti_itanium_print_si_class_type_info (&si_cti, colAddr, "");
        }

        if (r_str_cmp (flag->name, class_type_info_name, r_str_len_utf8 (flag->name))) {
                class_type_info cti;
                if (!rtti_itanium_read_class_type_info (context, colAddr, &cti)) {
                        eprintf ("Failed to parse Type Info at 0x%08"PFMT64x" (referenced from 0x%08"PFMT64x")\n", colAddr, colRefAddr);
                        return false;
                }
                rtti_itanium_print_class_type_info (&cti, colAddr, "");
        }
        return true;
}

R_API void r_anal_rtti_itanium_print_at_vtable (RVTableContext *context, ut64 addr, int mode) {
        rtti_itanium_print_class_type_info_recurse (context, addr);
}
