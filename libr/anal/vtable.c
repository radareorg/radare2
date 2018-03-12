/* radare - LGPL - Copyright 2009-2018 - pancake, maijin, thestr4ng3r */

#include "r_util.h"
#include "r_anal.h"

#define VTABLE_BUFF_SIZE 10

typedef enum {
	VTABLE_COMPILER_ITANIUM,
	VTABLE_COMPILER_MSVC
} VTableCompilerType;

typedef bool (*VTableReadAddr) (RAnal *anal, ut64 addr, ut64 *buf);
#define VTABLE_READ_ADDR_FUNC(fname, read_fname, sz) \
	bool fname(RAnal *anal, ut64 addr, ut64 *buf) { \
		ut8 tmp[sz]; \
		if(!anal->iob.read_at(anal->iob.io, addr, tmp, sz)) { \
			return false; \
		} \
		*buf = read_fname(tmp); \
		return true; \
	}
VTABLE_READ_ADDR_FUNC (vtable_read_addr_le8, r_read_le8, 1)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_le16, r_read_le16, 2)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_le32, r_read_le32, 4)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_le64, r_read_le64, 8)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_be8, r_read_be8, 1)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_be16, r_read_be16, 2)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_be32, r_read_be32, 4)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_be64, r_read_be64, 8)

typedef struct {
	RAnal *anal;
	VTableCompilerType compiler;
	ut8 wordSize;
	VTableReadAddr read_addr;
} VTableContext;


typedef struct vtable_info_t {
	ut64 saddr; //starting address
	int method_count;
	RList* methods;
} vtable_info;

typedef struct vtable_method_info_t {
	ut64 addr;           // addr of the function
	ut64 vtable_offset;  // offset inside the vtable
} vtable_method_info;


static void vtable_info_fini(vtable_info *vtable) {
	RListIter* iter;
	vtable_method_info *method;
	r_list_foreach (vtable->methods, iter, method) {
		free (method);
	}
	r_list_free (vtable->methods);
}

static ut64 vtable_info_get_size(VTableContext *context, vtable_info *vtable) {
	return (ut64)vtable->method_count * context->wordSize;
}


static bool vtable_begin(RAnal *anal, VTableContext *context) {
	context->anal = anal;
	context->compiler = VTABLE_COMPILER_ITANIUM;
	context->wordSize = (ut8)(anal->bits / 8);
	switch (anal->bits) {
		case 8:
			context->read_addr = anal->big_endian ? vtable_read_addr_be8 : vtable_read_addr_le8;
			break;
		case 16:
			context->read_addr = anal->big_endian ? vtable_read_addr_be16 : vtable_read_addr_le16;
			break;
		case 32:
			context->read_addr = anal->big_endian ? vtable_read_addr_be32 : vtable_read_addr_le32;
			break;
		case 64:
			context->read_addr = anal->big_endian ? vtable_read_addr_be64 : vtable_read_addr_le64;
			break;
		default:
			return false;
	}
	return true;
}

static RList* vtable_get_methods(VTableContext *context, vtable_info *table) {
	RAnal *anal = context->anal;
	RList* vtableMethods = r_list_new ();
	if (!table || !anal || !vtableMethods) {
		r_list_free (vtableMethods);
		return NULL;
	}

	int curMethod = 0;
	int totalMethods = table->method_count;
	ut64 startAddress = table->saddr;
	while (curMethod < totalMethods) {
		ut64 curAddressValue;
		vtable_method_info *methodInfo;
		if (context->read_addr (context->anal, startAddress, &curAddressValue)
			&& (methodInfo = (vtable_method_info *)malloc (sizeof (vtable_method_info)))) {
			methodInfo->addr = curAddressValue;
			methodInfo->vtable_offset = startAddress - table->saddr;
			r_list_append (vtableMethods, methodInfo);
		}
		startAddress += context->wordSize;
		curMethod++;
	}

	table->methods = vtableMethods;
	return vtableMethods;
}

static bool vtable_addr_in_text_section(VTableContext *context, ut64 curAddress) {
	//section of the curAddress
	RBinSection* value = context->anal->binb.get_vsect_at (context->anal->binb.bin, curAddress);
	//If the pointed value lies in .text section
	return value && !strcmp (value->name, ".text");
}

static bool vtable_is_value_in_text_section(VTableContext *context, ut64 curAddress) {
	//value at the current address
	ut64 curAddressValue;
	if (!context->read_addr (context->anal, curAddress, &curAddressValue)) {
		return false;
	}
	//if the value is in text section
	return vtable_addr_in_text_section (context, curAddressValue);
}

static bool vtable_section_can_contain_vtables(VTableContext *context, RBinSection *section) {
	return !strcmp(section->name, ".rodata") ||
		   !strcmp(section->name, ".rdata") ||
		   !strcmp(section->name, ".data.rel.ro");
}

static int vtable_is_addr_vtable_start(VTableContext *context, ut64 curAddress) {
	RAnalRef *xref;
	RListIter *xrefIter;

	if (!curAddress || curAddress == UT64_MAX) {
		return false;
	}
	if (!vtable_is_value_in_text_section (context, curAddress)) {
		return false;
	}
	// total xref's to curAddress
	RList *xrefs = r_anal_xrefs_get (context->anal, curAddress);
	if (r_list_empty (xrefs)) {
		return false;
	}
	r_list_foreach (xrefs, xrefIter, xref) {
		// section in which currenct xref lies
		if (vtable_addr_in_text_section (context, xref->addr)) {
			ut8 buf[VTABLE_BUFF_SIZE];
			context->anal->iob.read_at (context->anal->iob.io, xref->addr, buf, sizeof(buf));

			RAnalOp analop = { 0 };
			r_anal_op (context->anal, &analop, xref->addr, buf, sizeof(buf));

			if (analop.type == R_ANAL_OP_TYPE_MOV
				|| analop.type == R_ANAL_OP_TYPE_LEA) {
				return true;
			}

			r_anal_op_fini (&analop);
		}
	}
	return false;
}

RList* vtable_search(VTableContext *context) {
	RAnal *anal = context->anal;
	if (!anal) {
		return NULL;
	}

	RList *vtables = r_list_newf ((RListFree)free);
	if (!vtables) {
		return NULL;
	}

	RList *sections = anal->binb.get_sections (anal->binb.bin);
	if (!sections) {
		r_list_free (vtables);
		return NULL;
	}

	RListIter *iter;
	RBinSection *section;
	r_list_foreach (sections, iter, section) {
		if (!vtable_section_can_contain_vtables (context, section)) {
			continue;
		}

		// ut8 *segBuff = calloc (1, section->vsize);
		// r_io_read_at (core->io, section->vaddr, segBuff, section->vsize);

		ut64 startAddress = section->vaddr;
		ut64 endAddress = startAddress + (section->vsize) - context->wordSize;
		while (startAddress <= endAddress) {
			if (vtable_is_addr_vtable_start (context, startAddress)) {
				vtable_info *vtable = calloc (1, sizeof(vtable_info));
				vtable->saddr = startAddress;
				int noOfMethods = 0;
				while (vtable_is_value_in_text_section (context, startAddress)) {
					noOfMethods++;
					startAddress += context->wordSize;
				}
				vtable->method_count = noOfMethods;
				r_list_append (vtables, vtable);
				continue;
			}
			startAddress += 1;
		}
	}

	if (r_list_empty (vtables)) {
		// stripped binary?
		eprintf ("No virtual tables found\n");
		r_list_free (vtables);
		return NULL;
	}
	return vtables;
}

R_API void r_anal_list_vtables(RAnal *anal, int rad) {
	VTableContext context;
	vtable_begin (anal, &context);

	RList *vtableMethods;
	const char *noMethodName = "No Name found";
	RListIter* vtableMethodNameIter;
	vtable_method_info *curMethod;
	RListIter* vtableIter;
	vtable_info* table;

	RList* vtables = vtable_search (&context);
	if (!vtables) {
		return;
	}

	if (rad == 'j') {
		bool isFirstElement = true;
		r_cons_print ("[");
		r_list_foreach (vtables, vtableIter, table) {
			if (!isFirstElement) {
				r_cons_print (",");
			}
			bool isFirstMethod = true;
			r_cons_printf ("{\"offset\":%"PFMT64d",\"methods\":[", table->saddr);
			vtableMethods = vtable_get_methods (&context, table);
			r_list_foreach (vtableMethods, vtableMethodNameIter, curMethod) {
				if(!isFirstMethod)
					r_cons_print (",");
				RAnalFunction *fcn = r_anal_get_fcn_in (anal, curMethod->addr, 0);
				const char* const name = fcn ? fcn->name : NULL;
				r_cons_printf ("{\"offset\":%"PFMT64d",\"name\":\"%s\"}",
						curMethod->addr, name ? name : noMethodName);
				isFirstMethod = false;
			}
			r_cons_print ("]}");
			isFirstElement = false;
		}
		r_cons_println ("]");
	} else if (rad == '*') {
		r_list_foreach (vtables, vtableIter, table) {
			r_cons_printf ("f vtable.0x%08"PFMT64x" %"PFMT64d" @ 0x%08"PFMT64x"\n",
						   table->saddr,
						   vtable_info_get_size (&context, table),
						   table->saddr);
			vtableMethods = vtable_get_methods (&context, table);
			r_list_foreach (vtableMethods, vtableMethodNameIter, curMethod) {
				r_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", context.wordSize, table->saddr + curMethod->vtable_offset);
				RAnalFunction *fcn = r_anal_get_fcn_in (anal, curMethod->addr, 0);
				const char *const name = fcn ? fcn->name : NULL;
				if (name) {
					r_cons_printf ("f %s=0x%08"PFMT64x"\n", name, curMethod->addr);
				} else {
					r_cons_printf ("f method.virtual.0x%08"PFMT64x"=0x%08"PFMT64x"\n", curMethod->addr, curMethod->addr);
				}
			}
		}
	} else {
		r_list_foreach (vtables, vtableIter, table) {
			ut64 vtableStartAddress = table->saddr;
			vtableMethods = vtable_get_methods (&context, table);
			r_cons_printf ("\nVtable Found at 0x%08"PFMT64x"\n", vtableStartAddress);
			r_list_foreach (vtableMethods, vtableMethodNameIter, curMethod) {
				RAnalFunction *fcn = r_anal_get_fcn_in (anal, curMethod->addr, 0);
				const char* const name = fcn ? fcn->name : NULL;
				r_cons_printf ("0x%08"PFMT64x" : %s\n", vtableStartAddress, name ? name : noMethodName);
				vtableStartAddress += context.wordSize;
			}
			r_cons_newline ();
		}
	}
	r_list_foreach (vtables, vtableIter, table) {
		vtable_info_fini (table);
	}
	r_list_free (vtables);
}



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
	int signature;

	//within class offset
	int vftableOffset;

	//don't know what's this
	int cdOffset;

	//type descriptor for the current class
	type_descriptor* typeDescriptor;

	//hierarchy descriptor for current class
	class_hierarchy_descriptor* hierarchyDescriptor;
} rtti_complete_object_locator;

typedef struct run_time_type_information_t {
	ut64 vtable_start_addr;
	ut64 rtti_addr;
} rtti_struct;

static rtti_struct* get_rtti_data (RAnal *anal, ut64 atAddress) {
	// int wordSize = anal->bits / 8;
	// ut64 BaseLocatorAddr;
	// anal->iob.read_at (anal->iob.io, atAddress - wordSize, &BaseLocatorAddr, wordSize); //XXX
	// eprintf ("Trying to parse rtti at 0x%08"PFMT64x"\n", BaseLocatorAddr);
	return NULL;
}

RList* r_anal_parse_rtti (void *anal, bool printJson) {
	VTableContext context;
	vtable_begin ((RAnal *)anal, &context);
	RList* vtables = vtable_search (&context);
	RListIter* vtableIter;
	RList* rtti_structures = r_list_new ();
	vtable_info* table;

	if (vtables) {
		r_list_foreach (vtables, vtableIter, table) {
			rtti_struct* current_rtti = get_rtti_data ((RAnal *)anal, table->saddr);
			if (current_rtti) {
				current_rtti->vtable_start_addr = table->saddr;
				r_list_append (rtti_structures, current_rtti);
			}
		}
	}
	r_list_free (vtables);
	return rtti_structures;
}

R_API void r_anal_print_rtti (RAnal *anal) {
	eprintf ("Work in progress\n");
}
