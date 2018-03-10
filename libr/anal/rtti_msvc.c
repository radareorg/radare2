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

	//within class offset
	ut32 vftableOffset;

	//don't know what's this
	ut32 cdOffset;

	ut64 typeDescriptorAddr;
	ut64 classDescriptorAddr;

	//type descriptor for the current class
	type_descriptor *typeDescriptor;

	//hierarchy descriptor for current class
	class_hierarchy_descriptor *hierarchyDescriptor;
} rtti_complete_object_locator;

typedef struct run_time_type_information_t {
	ut64 vtable_start_addr;
	ut64 rtti_addr;
} rtti_struct;


static bool rtti_msvc_read_complete_object_locator(RVTableContext *context, ut64 addr, rtti_complete_object_locator *col) {
	ut8 buf[3*sizeof(ut32) + 2*sizeof(ut64)];
	int colSize = 3*sizeof(ut32) + 2*context->wordSize;
	if(colSize > sizeof(buf)) {
		return false;
	}

	if (!context->anal->iob.read_at(context->anal->iob.io, addr, buf, colSize)) {
		return false;
	}

	ut32 (*read_at_32)(const void *src, size_t offset) = context->anal->big_endian ? r_read_at_be32 : r_read_at_le32;
	col->signature = read_at_32 (buf, 0);
	col->vftableOffset = read_at_32 (buf, 4);
	col->cdOffset = read_at_32 (buf, 8);

	if (context->wordSize == 4) { //XXX
		col->typeDescriptorAddr = read_at_32 (buf, 12);
		col->classDescriptorAddr = read_at_32 (buf, 16);
	} else {
		col->typeDescriptorAddr = r_read_at_be64 (buf, 12);
		col->classDescriptorAddr = r_read_at_be64 (buf, 20);
	}

	return true;
}

static rtti_struct *get_rtti_data(RVTableContext *context, ut64 atAddress) {
	ut64 colAddr;
	if (!context->read_addr (context->anal, atAddress - context->wordSize, &colAddr)) {
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
			col.signature, col.vftableOffset, col.cdOffset, col.typeDescriptorAddr, col.classDescriptorAddr);

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
