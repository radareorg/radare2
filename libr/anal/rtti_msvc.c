/* radare - LGPL - Copyright 2009-2018 - pancake, maijin, thestr4ng3r */

#include <r_anal.h>
#include "r_anal.h"

/*
	RTTI Parsing Information
	MSVC(Microsoft visual studio compiler) rtti structure
	information:
*/

typedef struct type_descriptor_t {
	ut64 pVFTable;//Always point to type_info's vftable
	int spare;
	char* className;
} type_descriptor;

typedef struct class_hierarchy_descriptor_t {
	int signature;//always 0

	//bit 0 --> Multiple inheritance
	//bit 1 --> Virtual inheritance
	int attributes;

	//total no of base classes
	// including itself
	int numBaseClasses;

	//Array of base class descriptor's
	RList* baseClassArray;
} class_hierarchy_descriptor;

typedef struct base_class_descriptor_t {
	//Type descriptor of current base class
	type_descriptor* typeDescriptor;

	//Number of direct bases
	//of this base class
	int numContainedBases;

	//vftable offset
	int mdisp;

	// vbtable offset
	int pdisp;

	//displacement of the base class
	//vftable pointer inside the vbtable
	int vdisp;

	//don't know what's this
	int attributes;

	//class hierarchy descriptor
	//of this base class
	class_hierarchy_descriptor* classDescriptor;
} base_class_descriptor;

typedef struct rtti_complete_object_locator_t {
	ut32 signature;
	ut32 vtable_offset; // offset of the vtable within class
	ut32 cd_offset;     // constructor displacement offset
	ut64 type_descriptor_addr;
	ut64 class_descriptor_addr;
} rtti_complete_object_locator;

typedef struct rtti_class_hierarchy_descriptor_t {
	ut32 signature;
	ut32 attributes; // bit 0 set = multiple inheritance, bit 1 set = virtual inheritance
	ut32 num_base_classes;
	ut64 base_class_array_addr;
} rtti_class_hierarchy_descriptor;

typedef struct run_time_type_information_t {
	ut64 vtable_start_addr;
	ut64 rtti_addr;
} rtti_struct;


static bool rtti_msvc_read_complete_object_locator(RVTableContext *context, ut64 addr, rtti_complete_object_locator *col) {
	ut8 buf[3*sizeof(ut32) + 2*sizeof(ut64)];
	int colSize = 3*sizeof(ut32) + 2*context->word_size;
	if(colSize > sizeof(buf)) {
		return false;
	}

	if (!context->anal->iob.read_at(context->anal->iob.io, addr, buf, colSize)) {
		return false;
	}

	ut32 (*read_at_32)(const void *src, size_t offset) = context->anal->big_endian ? r_read_at_be32 : r_read_at_le32;
	col->signature = read_at_32 (buf, 0);
	col->vtable_offset = read_at_32 (buf, 4);
	col->cd_offset = read_at_32 (buf, 8);
	col->type_descriptor_addr = r_read_ble (buf + 12, (bool) context->anal->big_endian, context->word_size * 8);
	col->class_descriptor_addr = r_read_ble (buf + 12 + context->word_size, (bool) context->anal->big_endian, context->word_size * 8);
	return true;
}

static bool rtti_msvc_read_class_hierarchy_descriptor(RVTableContext *context, ut64 addr, rtti_class_hierarchy_descriptor *chd) {
	ut8 buf[3*sizeof(ut32) + sizeof(ut64)];
	int chdSize = 3*sizeof(ut32) + context->word_size;
	if(chdSize > sizeof(buf)) {
		return false;
	}

	if (!context->anal->iob.read_at(context->anal->iob.io, addr, buf, chdSize)) {
		return false;
	}

	ut32 (*read_at_32)(const void *src, size_t offset) = context->anal->big_endian ? r_read_at_be32 : r_read_at_le32;
	chd->signature = read_at_32 (buf, 0);
	chd->attributes = read_at_32 (buf, 4);
	chd->num_base_classes = read_at_32 (buf, 8);
	chd->base_class_array_addr = r_read_ble (buf + 12, (bool) context->anal->big_endian, context->word_size * 8);
	return true;
}



static rtti_struct *get_rtti_data(RVTableContext *context, ut64 atAddress) {
	ut64 colAddr;
	if (!context->read_addr (context->anal, atAddress - context->word_size, &colAddr)) {
		return NULL;
	}
	eprintf ("Trying to parse rtti at 0x%08"PFMT64x"\n", colAddr);

	rtti_complete_object_locator col;
	if (!rtti_msvc_read_complete_object_locator (context, colAddr, &col)) {
		return NULL;
	}

	eprintf ("Read Complete Object Locator:\n"
			"  signature: %#x\n"
			"  vftableOffset: %#x\n"
			"  cdOffset: %#x\n"
			"  typeDescriptorAddr: 0x%08"PFMT64x"\n"
			"  classDescriptorAddr: 0x%08"PFMT64x"\n\n",
			col.signature, col.vtable_offset, col.cd_offset,
			col.type_descriptor_addr, col.class_descriptor_addr);

	rtti_class_hierarchy_descriptor chd;
	if (rtti_msvc_read_class_hierarchy_descriptor (context, col.class_descriptor_addr, &chd)) {
		eprintf ("Read Class Hierarchy Decriptor:\n"
						 "  signature: %#x\n"
						 "  attributes: %#x\n"
						 "  numBaseClasses: %#x\n"
						 "  baseClassArrayAddr: 0x%08"PFMT64x"\n\n",
				 chd.signature, chd.attributes, chd.num_base_classes, chd.base_class_array_addr);
	} else {
		eprintf ("Failed to read Class Hierarchy Descriptor at 0x%08"PFMT64x"\n", col.class_descriptor_addr);
	}

	return NULL;
}

R_API RList *r_anal_rtti_msvc_parse(RVTableContext *context) {
	RList *vtables = r_anal_vtable_search (context);
	RListIter *vtableIter;
	RList *rtti_structures = r_list_new ();
	RVTableInfo *table;

	if (vtables) {
		r_list_foreach (vtables, vtableIter, table) {
			rtti_struct* current_rtti = get_rtti_data (context, table->saddr);
			if (current_rtti) {
				current_rtti->vtable_start_addr = table->saddr;
				r_list_append (rtti_structures, current_rtti);
			}
		}
	}
	r_list_free (vtables);
	return rtti_structures;
}
