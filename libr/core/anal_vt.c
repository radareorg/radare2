/* radare - LGPL - Copyright 2009-2018 - pancake, maijin */

#include "r_util.h"
#include "r_core.h"

#define VTABLE_BUFF_SIZE 10

typedef enum {
	VTABLE_COMPILER_ITANIUM,
	VTABLE_COMPILER_MSVC
} VTableCompilerType;

typedef struct {
	RCore *core;
	VTableCompilerType compiler;
	ut8 wordSize;
	bool bigendian;
} VTableContext;

typedef struct vtable_info_t {
	ut64 saddr; //starting address
	int methods;
	RList* funtions;
} vtable_info;


static void vtable_begin(RCore *core, VTableContext *context) {
	context->core = core;
	context->compiler = VTABLE_COMPILER_ITANIUM;
	ut64 bits = r_config_get_i (core->config, "asm.bits");
	context->wordSize = (ut8)(bits / 8);
	context->bigendian = r_config_get_i (core->config, "asm.bigendian") != 0;
}

static RList* vtable_get_methods(VTableContext *context, vtable_info *table) {
	RCore *core = context->core;
	RList* vtableMethods = r_list_new ();
	if (table && core && vtableMethods) {
		int curMethod = 0;
		int totalMethods = table->methods;
		ut64 startAddress = table->saddr;
		while (curMethod < totalMethods) {
			ut64 curAddressValue;
			r_io_read_i (core->io, startAddress, &curAddressValue, 8, false);	//XXX
			RAnalFunction *curFuntion = r_anal_get_fcn_in (core->anal, curAddressValue, 0);
			r_list_append (vtableMethods, curFuntion);
			startAddress += context->wordSize;
			curMethod++;
		}
		table->funtions = vtableMethods;
		return vtableMethods;
	}
	r_list_free (vtableMethods);
	return NULL;
}

static int vtable_addr_in_text_section(VTableContext *context, ut64 curAddress) {
	//section of the curAddress
	RBinSection* value = r_bin_get_section_at (context->core->bin->cur->o, curAddress, true);
	//If the pointed value lies in .text section
	return value && !strcmp (value->name, ".text");
}

static int vtable_is_value_in_text_section(VTableContext *context, ut64 curAddress) {
	//value at the current address
	ut64 curAddressValue;
	r_io_read_i (context->core->io, curAddress, &curAddressValue, 8, false);	//XXX
	//if the value is in text section
	return vtable_addr_in_text_section (context, curAddressValue);
}

static bool vtable_section_can_contain_vtables(VTableContext *context, RBinSection *section) {
	return !strcmp(section->name, ".rodata") ||
		   !strcmp(section->name, ".rdata") ||
		   !strcmp(section->name, ".data.rel.ro");
}

static int vtable_is_addr_vtable_start(VTableContext *context, ut64 curAddress) {
	RAsmOp asmop = R_EMPTY;
	RAnalRef *xref;
	RListIter *xrefIter;
	ut8 buf[VTABLE_BUFF_SIZE];
	if (!curAddress || curAddress == UT64_MAX) {
		return false;
	}
	if (!vtable_is_value_in_text_section (context, curAddress)) {
		return false;
	}
	// total xref's to curAddress
	RList *xrefs = r_anal_xrefs_get (context->core->anal, curAddress);
	if (r_list_empty (xrefs)) {
		return false;
	}
	r_list_foreach (xrefs, xrefIter, xref) {
		// section in which currenct xref lies
		if (vtable_addr_in_text_section (context, xref->addr)) {
			r_io_read_at (context->core->io, xref->addr, buf, VTABLE_BUFF_SIZE);
			if (!r_asm_disassemble (context->core->assembler, &asmop, buf, VTABLE_BUFF_SIZE) > 0) {
				continue;
			}
			if ((!strncmp (asmop.buf_asm, "mov", 3)) ||
				(!strncmp (asmop.buf_asm, "lea", 3))) {
				return true;
			}
		}
	}
	return false;
}

RList* vtable_search(VTableContext *context) {
	RCore *core = context->core;
	if (!core) {
		return NULL;
	}
	ut64 startAddress;
	ut64 endAddress;
	RListIter * iter;
	RBinSection *section;
	RList *vtables = r_list_newf ((RListFree)free);
	if (!vtables) {
		return NULL;
	}
	RList *sections = r_bin_get_sections (core->bin);
	if (!sections) {
		r_list_free (vtables);
		return NULL;
	}
	ut64 bits = r_config_get_i (core->config, "asm.bits");
	int wordSize = bits / 8;
	r_list_foreach (sections, iter, section) {
		if (!vtable_section_can_contain_vtables (context, section)) {
			continue;
		}
		ut8 *segBuff = calloc (1, section->vsize);
		r_io_read_at (core->io, section->vaddr, segBuff, section->vsize);
		startAddress = section->vaddr;
		endAddress = startAddress + (section->vsize) - wordSize;
		while (startAddress <= endAddress) {
			if (vtable_is_addr_vtable_start (context, startAddress)) {
				vtable_info *vtable = calloc (1, sizeof(vtable_info));
				vtable->saddr = startAddress;
				int noOfMethods = 0;
				while (vtable_is_value_in_text_section (context, startAddress)) {
					noOfMethods++;
					startAddress += wordSize;
				}
				vtable->methods = noOfMethods;
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

R_API void r_core_anal_list_vtables(void *core, bool printJson) {
	VTableContext context;
	vtable_begin (core, &context);
	RList* vtables = vtable_search (&context);
	RList *vtableMethods;
	const char *noMethodName = "No Name found";
	RListIter* vtableMethodNameIter;
	RAnalFunction *curMethod;
	RListIter* vtableIter;
	vtable_info* table;

	if (!vtables) {
		return;
	}
	if (printJson) {
		bool isFirstElement = true;
		r_cons_print ("[");
		r_list_foreach (vtables, vtableIter, table) {
			if (!isFirstElement) {
				r_cons_print (",");
			}
			bool isFirstMethod = true;
			r_cons_printf ("{\"offset\":%"PFMT64d",\"methods\":[", table->saddr);
			vtableMethods = vtable_get_methods (&context, table);
			if(vtableMethods)
				r_list_foreach (vtableMethods, vtableMethodNameIter, curMethod) {
					if(!isFirstMethod)
						r_cons_print (",");
					const char* const name = curMethod->name;
					r_cons_printf ("{\"offset\":%"PFMT64d",\"name\":\"%s\"}",
						curMethod->addr, name? name : noMethodName);
					isFirstMethod = false;
				}
			r_cons_print ("]}");
			isFirstElement = false;
		}
		r_cons_println ("]");
	} else {
		r_list_foreach (vtables, vtableIter, table) {
			ut64 vtableStartAddress = table->saddr;
			vtableMethods = vtable_get_methods (&context, table);
			if (vtableMethods) {
				r_cons_printf ("\nVtable Found at 0x%08"PFMT64x"\n", 
				  		vtableStartAddress);
				r_list_foreach (vtableMethods, vtableMethodNameIter, curMethod) {
					if (curMethod->name) {
						r_cons_printf ("0x%08"PFMT64x" : %s\n", 
						  		vtableStartAddress, curMethod->name);
					} else {
						r_cons_printf ("0x%08"PFMT64x" : %s\n", 
						  		vtableStartAddress, noMethodName);
					}
					vtableStartAddress += context.wordSize;
				}
				r_cons_newline ();
			}
		}
	}
	r_list_free (vtables);
}

static void r_core_anal_list_vtables_all(void *core) {
	VTableContext context;
	vtable_begin ((RCore *)core, &context);
	RList* vtables = vtable_search (&context);
	RListIter* vtableIter;
	RListIter* vtableMethodNameIter;
	RAnalFunction* function;
	vtable_info* table;

	r_list_foreach (vtables, vtableIter, table) {
		RList *vtableMethods = vtable_get_methods (&context, table);
		r_list_foreach (vtableMethods, vtableMethodNameIter, function) {
			// char *ret = r_str_newf ("vtable.%s", table->funtio);
			r_cons_printf ("f %s=0x%08"PFMT64x"\n", function->name, function->addr);
		}
	}
	r_list_free (vtables);
}

static rtti_struct* get_rtti_data (RCore *core, ut64 atAddress) {
	ut64 bits = r_config_get_i (core->config, "asm.bits");
	int wordSize = bits / 8;
	ut64 BaseLocatorAddr;
	r_io_read_i (core->io, atAddress - wordSize, &BaseLocatorAddr, wordSize, false);	//XXX
	eprintf ("Trying to parse rtti at 0x%08"PFMT64x"\n", BaseLocatorAddr);
	return NULL;
}

RList* r_core_anal_parse_rtti (void *core, bool printJson) {
	VTableContext context;
	vtable_begin ((RCore *)core, &context);
	RList* vtables = vtable_search (&context);
	RListIter* vtableIter;
	RList* rtti_structures = r_list_new ();
	vtable_info* table;

	if (vtables) {
		r_list_foreach (vtables, vtableIter, table) {
			rtti_struct* current_rtti = get_rtti_data ((RCore *)core, table->saddr);
			if (current_rtti) {
				current_rtti->vtable_start_addr = table->saddr;
				r_list_append (rtti_structures, current_rtti);
			}
		}
	}
	r_list_free (vtables);
	return rtti_structures;
}

R_API void r_core_anal_print_rtti (void *core) {
	eprintf ("Work in progress\n");
}
