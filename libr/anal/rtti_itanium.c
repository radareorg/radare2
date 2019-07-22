/* radare - LGPL - Copyright 2018 - pancake, r00tus3r */

#include <r_anal.h>
#include <r_core.h>
#include <r_flag.h>
#include <r_cons.h>

#define VMI_CLASS_TYPE_INFO_NAME "obj.vtable_for___cxxabiv1::__vmi_class_type_info"
#define CLASS_TYPE_INFO_NAME "obj.vtable_for___cxxabiv1::__class_type_info"
#define SI_CLASS_TYPE_INFO_NAME "obj.vtable_for___cxxabiv1::__si_class_type_info"
#define NAME_BUF_SIZE 64

typedef struct class_type_info_t {
	ut32 vtable_addr;
	ut32 name_addr;
	char *name;
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
	char *name;
	ut32 base_class_addr;
} si_class_type_info;

typedef struct vmi_class_type_info_t {
	ut32 vtable_addr;
	ut32 name_addr;
	char *name;
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

static void rtti_itanium_class_type_info_fini (class_type_info *cti) {
	if (cti) {
		free (cti->name);
	}
}

static bool rtti_itanium_read_class_type_info (RVTableContext *context, ut64 addr, class_type_info *cti) {
	ut64 at;
	if (addr == UT64_MAX) {
		return false;
	}
	if (!context->read_addr (context->anal, addr, &at)) {
		return false;
	}
	cti->vtable_addr = at;
	if (!context->read_addr (context->anal, addr + context->word_size, &at)) {
		return false;
	}
	cti->name_addr = at;
	ut8 buf[NAME_BUF_SIZE];
	if (!context->anal->iob.read_at (context->anal->iob.io, at, buf, sizeof(buf))) {
		return false;
	}
	size_t name_len = r_str_len_utf8 ((const char *)buf) + 1;
	cti->name = malloc (name_len);
	if (!cti->name) {
		return false;
	}
	memcpy (cti->name, buf, name_len);
	return true;
}

static void rtti_itanium_vmi_class_type_info_fini (vmi_class_type_info *vmi_cti) {
	if (vmi_cti) {
		free (vmi_cti->vmi_bases);
		free (vmi_cti->name);
	}
}

static bool rtti_itanium_read_vmi_class_type_info (RVTableContext *context, ut64 addr, vmi_class_type_info *vmi_cti) {
	ut64 at;
	if (addr == UT64_MAX) {
		return false;
	}
	if (!context->read_addr (context->anal, addr, &at)) {
		return false;
	}
	vmi_cti->vtable_addr = at;
	addr += context->word_size;
	if (!context->read_addr (context->anal, addr, &at)) {
		return false;
	}
	vmi_cti->name_addr = at;
	ut8 buf[NAME_BUF_SIZE];
	if (!context->anal->iob.read_at (context->anal->iob.io, at, buf, sizeof(buf))) {
		return false;
	}
	size_t name_len = r_str_len_utf8 ((const char *)buf) + 1;
	vmi_cti->name = malloc (name_len);
	if (!vmi_cti->name) {
		return false;
	}
	memcpy (vmi_cti->name, buf, name_len);
	addr += context->word_size;
	if (!context->read_addr (context->anal, addr, &at)) {
		return false;
	}
	vmi_cti->vmi_flags = at;
	addr += 0x4;
	if (!context->read_addr (context->anal, addr, &at)) {
		return false;
	}
	if (at < 1 || at > 0xfffff) {
		eprintf ("Error reading vmi_base_count\n");
		return false;
	}
	vmi_cti->vmi_base_count = at;
	vmi_cti->vmi_bases = calloc (sizeof (base_class_type_info), vmi_cti->vmi_base_count);
	if (!vmi_cti->vmi_bases) {
		return false;
	}
	ut64 tmp_addr = addr + 0x4;

	int i;
	for (i = 0; i < vmi_cti->vmi_base_count; i++) {
		if (!context->read_addr (context->anal, tmp_addr, &at)) {
			return false;
		}
		vmi_cti->vmi_bases[i].base_class_addr = at;
		tmp_addr += context->word_size;
		if (!context->read_addr (context->anal, tmp_addr, &at)) {
			return false;
		}
		vmi_cti->vmi_bases[i].flags = at;
		tmp_addr += context->word_size;
	}
	return true;
}

static void rtti_itanium_si_class_type_info_fini (si_class_type_info *si_cti) {
	if (si_cti) {
		free (si_cti->name);
	}
}

static bool rtti_itanium_read_si_class_type_info (RVTableContext *context, ut64 addr, si_class_type_info *si_cti) {
	ut64 at;
	if (addr == UT64_MAX) {
		return false;
	}
	if (!context->read_addr (context->anal, addr, &at)) {
		return false;
	}
	si_cti->vtable_addr = at;
	if (!context->read_addr (context->anal, addr + context->word_size, &at)) {
		return false;
	}
	si_cti->name_addr = at;
	ut8 buf[NAME_BUF_SIZE];
	if (!context->anal->iob.read_at (context->anal->iob.io, at, buf, sizeof(buf))) {
		return false;
	}
	size_t name_len = r_str_len_utf8 ((const char *)buf) + 1;
	si_cti->name = malloc (name_len);
	if (!si_cti->name) {
		return false;
	}
	memcpy (si_cti->name, buf, name_len);
	if (!context->read_addr (context->anal, addr + 2 * context->word_size, &at)) {
		return false;
	}
	si_cti->base_class_addr = at;
	return true;
}

static void rtti_itanium_print_class_type_info (class_type_info *cti, ut64 addr, const char *prefix) {
	r_cons_printf ("%sType Info at 0x%08"PFMT64x ":\n"
			"%s  Reference to RTTI's type class: 0x%08"PFMT32x "\n"
			"%s  Reference to type's name: 0x%08"PFMT32x "\n"
			"%s  Type Name: %s\n",
			prefix, addr,
			prefix, cti->vtable_addr,
			prefix, cti->name_addr,
			prefix, cti->name + 1);
}

static void rtti_itanium_print_class_type_info_json (class_type_info *cti, ut64 addr) {
	r_cons_printf ("{\"type_info\": {\"found_at\":%"PFMT32u",\"ref_to_type_class\":%"PFMT32u","
			"\"ref_to_type_name\": %"PFMT32u"}}",
			addr, cti->vtable_addr, cti->name_addr);
}

static void rtti_itanium_print_vmi_class_type_info (vmi_class_type_info *vmi_cti, ut64 addr, const char *prefix) {
	r_cons_printf ("%sVMI Type Info at 0x%08"PFMT64x ":\n"
			"%s  Reference to RTTI's type class: 0x%08"PFMT32x "\n"
			"%s  Reference to type's name: 0x%08"PFMT32x "\n"
			"%s  Type Name: %s\n"
			"%s  Flags: 0x%x" "\n"
			"%s  Count of base classes: 0x%x" "\n",
			prefix, addr,
			prefix, vmi_cti->vtable_addr,
			prefix, vmi_cti->name_addr,
			prefix, vmi_cti->name + 1,
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

static void rtti_itanium_print_vmi_class_type_info_json (vmi_class_type_info *vmi_cti, ut64 addr) {
	r_cons_printf ("{\"vmi_type_info\": {\"found_at\":%"PFMT32u",\"ref_to_type_class\":%"PFMT32u","
			"\"ref_to_type_name\":%"PFMT32u",\"flags\":%"PFMT32d","
			"\"count_of_base_classes\":%"PFMT32d",",
			addr, vmi_cti->vtable_addr, vmi_cti->name_addr, vmi_cti->vmi_flags,
			vmi_cti->vmi_base_count);
	r_cons_printf ("\"base_classes\":[");
	int i;
	for (i = 0; i < vmi_cti->vmi_base_count; i++) {
		r_cons_printf("{\"type_desc_addr\":%"PFMT32u",\"flags\":%"PFMT32d"}",
				vmi_cti->vmi_bases[i].base_class_addr,
				vmi_cti->vmi_bases[i].flags);
		if (i < vmi_cti->vmi_base_count - 1) {
			r_cons_printf(",");
		}
	}
	r_cons_printf ("]}}");
}

static void rtti_itanium_print_si_class_type_info (si_class_type_info *si_cti, ut64 addr, const char *prefix) {
	r_cons_printf ("%sSI Type Info at 0x%08"PFMT64x ":\n"
			"%s  Reference to RTTI's type class: 0x%08"PFMT32x "\n"
			"%s  Reference to type's name: 0x%08"PFMT32x "\n"
			"%s  Type Name: %s\n"
			"%s  Reference to parent's type name: 0x%08"PFMT32x "\n",
			prefix, addr,
			prefix, si_cti->vtable_addr,
			prefix, si_cti->name_addr,
			prefix, si_cti->name + 1,
			prefix, si_cti->base_class_addr);
}

static void rtti_itanium_print_si_class_type_info_json (si_class_type_info *si_cti, ut64 addr) {
	r_cons_printf ("{\"si_type_info\": {\"found_at\":%"PFMT32u",\"ref_to_type_class\":%"PFMT32u","
			"\"ref_to_type_name\": %"PFMT32u",\"ref_to_parent_type_name\":%"PFMT32u"}}",
			addr, si_cti->vtable_addr, si_cti->name_addr, si_cti->base_class_addr);
}

R_API void r_anal_rtti_itanium_print_class_type_info(RVTableContext *context, ut64 addr, int mode) {
	class_type_info cti;
	if (!rtti_itanium_read_class_type_info (context, addr, &cti)) {
		eprintf ("Failed to parse Type Info at 0x%08"PFMT64x"\n", addr);
		return;
	}
	if (mode == 'j') {
		rtti_itanium_print_class_type_info_json (&cti, addr);
	} else {
		rtti_itanium_print_class_type_info (&cti, addr, "");
	}

	rtti_itanium_class_type_info_fini (&cti);
}

R_API void r_anal_rtti_itanium_print_si_class_type_info(RVTableContext *context, ut64 addr, int mode) {
	si_class_type_info si_cti = {0};
	if (!rtti_itanium_read_si_class_type_info (context, addr, &si_cti)) {
		eprintf ("Failed to parse Type Info at 0x%08"PFMT64x"\n", addr);
		goto beach;
	}
	if (mode == 'j') {
		rtti_itanium_print_si_class_type_info_json (&si_cti, addr);
	} else {
		rtti_itanium_print_si_class_type_info (&si_cti, addr, "");
	}

beach:
	rtti_itanium_si_class_type_info_fini (&si_cti);
}

R_API void r_anal_rtti_itanium_print_vmi_class_type_info(RVTableContext *context, ut64 addr, int mode) {
	vmi_class_type_info vmi_cti = {0};
	if (!rtti_itanium_read_vmi_class_type_info (context, addr, &vmi_cti)) {
		eprintf ("Failed to parse Type Info at 0x%08"PFMT64x"\n", addr);
		goto beach;
	}
	if (mode == 'j') {
		rtti_itanium_print_vmi_class_type_info_json (&vmi_cti, addr);
	} else {
		rtti_itanium_print_vmi_class_type_info (&vmi_cti, addr, "");
	}

beach:
	rtti_itanium_vmi_class_type_info_fini (&vmi_cti);
}

static bool rtti_itanium_print_class_type_info_recurse(RVTableContext *context, ut64 atAddress, int mode) {
	bool use_json = mode == 'j';
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

	flag = context->anal->flag_get (core->flags, class_type_offset);
	if (!flag) {
		eprintf ("No RTTI found\n");
		return false;
	}
	if (!r_str_cmp (flag->name, VMI_CLASS_TYPE_INFO_NAME, r_str_len_utf8 (flag->name))) {
		vmi_class_type_info vmi_cti = {0};
		if (!rtti_itanium_read_vmi_class_type_info (context, colAddr, &vmi_cti)) {
			eprintf ("Failed to parse Type Info at 0x%08"PFMT64x" (referenced from 0x%08"PFMT64x")\n", colAddr, colRefAddr);
			rtti_itanium_vmi_class_type_info_fini (&vmi_cti);
			return false;
		}
		if (use_json) {
			rtti_itanium_print_vmi_class_type_info_json (&vmi_cti, colAddr);
		} else {
			rtti_itanium_print_vmi_class_type_info (&vmi_cti, colAddr, "");
		}

		rtti_itanium_vmi_class_type_info_fini (&vmi_cti);
	}

	if (!r_str_cmp (flag->name, SI_CLASS_TYPE_INFO_NAME, r_str_len_utf8 (flag->name))) {
		si_class_type_info si_cti = {0};
		if (!rtti_itanium_read_si_class_type_info (context, colAddr, &si_cti)) {
			eprintf ("Failed to parse Type Info at 0x%08"PFMT64x" (referenced from 0x%08"PFMT64x")\n", colAddr, colRefAddr);
			rtti_itanium_si_class_type_info_fini (&si_cti);
			return false;
		}
		if (use_json) {
			rtti_itanium_print_si_class_type_info_json (&si_cti, colAddr);
		} else {
			rtti_itanium_print_si_class_type_info (&si_cti, colAddr, "");
		}

		rtti_itanium_si_class_type_info_fini (&si_cti);
	}

	if (!r_str_cmp (flag->name, CLASS_TYPE_INFO_NAME, r_str_len_utf8 (flag->name))) {
		class_type_info cti;
		if (!rtti_itanium_read_class_type_info (context, colAddr, &cti)) {
			eprintf ("Failed to parse Type Info at 0x%08"PFMT64x" (referenced from 0x%08"PFMT64x")\n", colAddr, colRefAddr);
			return false;
		}
		if (use_json) {
			rtti_itanium_print_class_type_info_json (&cti, colAddr);
		} else {
			rtti_itanium_print_class_type_info (&cti, colAddr, "");
		}

		rtti_itanium_class_type_info_fini (&cti);
	}
	return true;
}

R_API void r_anal_rtti_itanium_print_at_vtable (RVTableContext *context, ut64 addr, int mode) {
	rtti_itanium_print_class_type_info_recurse (context, addr, mode);
}
