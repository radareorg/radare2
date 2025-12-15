/* radare - LGPL - Copyright 2025 - pancake */

#include <r_bin.h>
#include "../i/private.h"
#include "../format/pdb/types.h"
#include "../format/pdb/omap.h"

// Forward declarations for PDB internal structures needed by the plugin
typedef void(*parse_stream_)(void *stream, R_STREAM_FILE *stream_file);

typedef struct {
	int indx;
	parse_stream_ parse_stream;
	void *stream;
	EStream type;
	free_func free;
} SStreamParseFunc;

#define PDB7_SIGNATURE "Microsoft C/C++ MSF 7.00\r\n\x1A" \
		"DS\0\0\0"
#define PDB7_SIGNATURE_LEN 32

typedef struct {
	RBinPdb pdb;
} RBinPDBObj;

static bool check(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) < PDB7_SIGNATURE_LEN) {
		return false;
	}
	char signature[PDB7_SIGNATURE_LEN];
	if (r_buf_read_at (b, 0, (ut8 *)signature, PDB7_SIGNATURE_LEN) != PDB7_SIGNATURE_LEN) {
		return false;
	}
	return !memcmp (signature, PDB7_SIGNATURE, PDB7_SIGNATURE_LEN);
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && buf, false);
	RBinPDBObj *res = R_NEW0 (RBinPDBObj);
	if (!res) {
		return false;
	}
	if (!r_bin_pdb_parser (&res->pdb, bf->file)) {
		free (res);
		return false;
	}
	if (!res->pdb.pdb_parse (&res->pdb)) {
		res->pdb.finish_pdb_parse (&res->pdb);
		free (res);
		return false;
	}
	bf->bo->bin_obj = res;
	return true;
}

static void destroy(RBinFile *bf) {
	RBinPDBObj *obj = bf->bo->bin_obj;
	if (obj) {
		obj->pdb.finish_pdb_parse (&obj->pdb);
		free (obj);
	}
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->type = strdup ("PDB (Program Database)");
	ret->bclass = strdup ("PDB");
	ret->rclass = strdup ("pdb");
	ret->arch = strdup ("x86"); // maybe its arm
	ret->machine = strdup ("Microsoft PDB");
	ret->os = strdup ("Windows");
	ret->bits = 64;
	ret->has_va = false;
	return ret;
}

static RList *symbols(RBinFile *bf) {
	RList *ret = r_list_newf ((RListFree)r_bin_symbol_free);
	if (!ret) {
		return NULL;
	}
	RBinPDBObj *obj = bf->bo->bin_obj;
	if (!obj || !obj->pdb.pdb_streams2) {
		return ret;
	}

	// Extract symbols from PDB global symbol stream
	SStreamParseFunc *omap = NULL, *sctns = NULL, *sctns_orig = NULL, *gsym = NULL, *tmp = NULL;
	SIMAGE_SECTION_HEADER *sctn_header = NULL;
	SGDATAStream *gsym_data_stream = NULL;
	SPEStream *pe_stream = NULL;
	SGlobal *gdata = NULL;
	RListIter *it = NULL;
	RList *l = obj->pdb.pdb_streams2;

	it = r_list_iterator (l);
	while (r_list_iter_next (it)) {
		tmp = (SStreamParseFunc *)r_list_iter_get (it);
		switch (tmp->type) {
		case ePDB_STREAM_SECT__HDR_ORIG:
			sctns_orig = tmp;
			break;
		case ePDB_STREAM_SECT_HDR:
			sctns = tmp;
			break;
		case ePDB_STREAM_OMAP_FROM_SRC:
			omap = tmp;
			break;
		case ePDB_STREAM_GSYM:
			gsym = tmp;
			break;
		default:
			break;
		}
	}

	if (!gsym) {
		return ret;
	}

	gsym_data_stream = (SGDATAStream *)gsym->stream;
	if ((omap != NULL) && (sctns_orig != NULL)) {
		pe_stream = (SPEStream *)sctns_orig->stream;
	} else if (sctns) {
		pe_stream = (SPEStream *)sctns->stream;
	}

	if (!pe_stream || !gsym_data_stream || !gsym_data_stream->globals_list) {
		return ret;
	}

	it = r_list_iterator (gsym_data_stream->globals_list);
	while (r_list_iter_next (it)) {
		gdata = (SGlobal *)r_list_iter_get (it);
		if (!gdata || !gdata->name.name) {
			continue;
		}

		sctn_header = r_list_get_n (pe_stream->sections_hdrs, (gdata->segment - 1));
		if (sctn_header) {
			RBinSymbol *sym = R_NEW0 (RBinSymbol);
			if (!sym) {
				continue;
			}

			char *demangled_name = r_bin_demangle_msvc (gdata->name.name);
			const char *name = demangled_name? demangled_name: gdata->name.name;

			sym->name = r_bin_name_new (name);
			sym->vaddr = bf->bo->baddr + omap_remap ((omap)? (omap->stream): NULL, gdata->offset + sctn_header->virtual_address);
			sym->paddr = gdata->offset;
			sym->size = 0; // PDB doesn't provide symbol sizes
			sym->type = (gdata->symtype == 2)? "FUNC": "OBJ";
			sym->bind = "GLOBAL";
			sym->attr = R_BIN_ATTR_GLOBAL;

			r_list_append (ret, sym);
			free (demangled_name);
		}
	}

	return ret;
}

static R_BORROW RList *lines(RBinFile *bf) {
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	RBinPDBObj *obj = bf->bo->bin_obj;
	if (!obj) {
		return ret;
	}
	// TODO: Extract source line information from PDB
	// This would involve parsing the line number streams
	return ret;
}

static char *types(RBinFile *bf) {
	RBinPDBObj *obj = bf->bo->bin_obj;
	if (!obj || !obj->pdb.pdb_streams) {
		return NULL;
	}

	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}

	// Get the TPI stream from the streams list
	STpiStream *tpi_stream = r_list_get_n (obj->pdb.pdb_streams, ePDB_STREAM_TPI);
	if (!tpi_stream || !tpi_stream->types) {
		r_strbuf_free (sb);
		return NULL;
	}

	// Iterate through all types and extract struct/union/enum definitions
	RListIter *it = r_list_iterator (tpi_stream->types);
	while (r_list_iter_next (it)) {
		SType *type = r_list_iter_get (it);
		if (!type) {
			continue;
		}

		STypeInfo *type_info = &type->type_data;
		switch (type_info->leaf_type) {
		case eLF_STRUCTURE:
		case eLF_CLASS: {
			char *name = NULL;
			char *name_to_free = NULL;
			if (type_info->get_name) {
				type_info->get_name (tpi_stream, type_info, &name);
			}
			if (!name) {
				name = name_to_free = r_str_newf ("struct_0x%x", type->tpi_idx);
			}
			r_strbuf_appendf (sb, "struct %s {\n", name);
			if (type_info->get_members) {
				RList *members = NULL;
				type_info->get_members (tpi_stream, type_info, &members);
				if (members) {
					RListIter *member_it = r_list_iterator (members);
					while (r_list_iter_next (member_it)) {
						STypeInfo *member_info = r_list_iter_get (member_it);
						if (member_info && member_info->leaf_type == eLF_MEMBER) {
							char *member_name = NULL;
							char *member_type = NULL;
							if (member_info->get_name) {
								member_info->get_name (tpi_stream, member_info, &member_name);
							}
							if (member_info->get_print_type) {
								member_info->get_print_type (tpi_stream, member_info, &member_type);
							}
							if (member_name && member_type) {
								r_strbuf_appendf (sb, "  %s %s;\n", member_type, member_name);
							}
							free (member_type);
						}
					}
				}
			}
			r_strbuf_append (sb, "};\n\n");
			free (name_to_free);
			break;
		}
		case eLF_UNION: {
			char *name = NULL;
			char *name_to_free = NULL;
			if (type_info->get_name) {
				type_info->get_name (tpi_stream, type_info, &name);
			}
			if (!name) {
				name = name_to_free = r_str_newf ("union_0x%x", type->tpi_idx);
			}
			r_strbuf_appendf (sb, "union %s {\n", name);
			if (type_info->get_members) {
				RList *members = NULL;
				type_info->get_members (tpi_stream, type_info, &members);
				if (members) {
					RListIter *member_it = r_list_iterator (members);
					while (r_list_iter_next (member_it)) {
						STypeInfo *member_info = r_list_iter_get (member_it);
						if (member_info && member_info->leaf_type == eLF_MEMBER) {
							char *member_name = NULL;
							char *member_type = NULL;
							if (member_info->get_name) {
								member_info->get_name (tpi_stream, member_info, &member_name);
							}
							if (member_info->get_print_type) {
								member_info->get_print_type (tpi_stream, member_info, &member_type);
							}
							if (member_name && member_type) {
								r_strbuf_appendf (sb, "  %s %s;\n", member_type, member_name);
							}
							free (member_type);
						}
					}
				}
			}
			r_strbuf_append (sb, "};\n\n");
			free (name_to_free);
			break;
		}
		case eLF_ENUM: {
			char *name = NULL;
			char *name_to_free = NULL;
			if (type_info->get_name) {
				type_info->get_name (tpi_stream, type_info, &name);
			}
			if (!name) {
				name = name_to_free = r_str_newf ("enum_0x%x", type->tpi_idx);
			}
			r_strbuf_appendf (sb, "enum %s {\n", name);
			if (type_info->get_members) {
				RList *members = NULL;
				type_info->get_members (tpi_stream, type_info, &members);
				if (members) {
					RListIter *member_it = r_list_iterator (members);
					while (r_list_iter_next (member_it)) {
						STypeInfo *member_info = r_list_iter_get (member_it);
						if (member_info && member_info->leaf_type == eLF_ENUMERATE) {
							char *enum_name = NULL;
							int enum_val = 0;
							if (member_info->get_name) {
								member_info->get_name (tpi_stream, member_info, &enum_name);
							}
							if (member_info->get_val) {
								member_info->get_val (tpi_stream, member_info, &enum_val);
							}
							if (enum_name) {
								r_strbuf_appendf (sb, "  %s = %d,\n", enum_name, enum_val);
							}
						}
					}
				}
			}
			r_strbuf_append (sb, "};\n\n");
			free (name_to_free);
			break;
		}
		default:
			break;
		}
	}

	char *ret = r_strbuf_drain (sb);
	return ret && *ret? ret: NULL;
}

RBinPlugin r_bin_plugin_pdb = {
	.meta = {
		.name = "pdb",
		.desc = "Microsoft Program Database format",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.symbols = &symbols,
	.lines = &lines,
	.types = &types,
	.info = &info,
	.minstrlen = 0,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pdb,
	.version = R2_VERSION
};
#endif
