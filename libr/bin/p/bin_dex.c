/* radare - LGPL - Copyright 2011-2016 - pancake */
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "dex/dex.h"
#define r_hash_adler32 __adler32
#include "../../hash/adler32.c"

#define DEBUG_PRINTF 0

#if DEBUG_PRINTF
#define dprintf eprintf
#else
#define dprintf if (0)eprintf
#endif

static Sdb *mdb = NULL;

static char *getstr(RBinDexObj *bin, int idx) {
	ut8 buf[6];
	ut64 len;
	int uleblen;
	if (!bin || idx < 0 || idx >= bin->header.strings_size || !bin->strings) {
		return NULL;
	}
	if (bin->strings[idx] >= bin->size) {
		return NULL;
	}

	r_buf_read_at (bin->b, bin->strings[idx], buf, sizeof (buf));
	uleblen = r_uleb128 (buf, sizeof (buf), &len) - buf;
	if (!uleblen || uleblen >= bin->size) {
		return NULL;
	}
	if (!len || len >= bin->size) {
		return NULL;
	}
	// TODO: improve this ugly fix
	char c = 'a';
	while (c) {
		r_buf_read_at (bin->b, (bin->strings[idx]) + uleblen + len, (ut8*)&c, 1);
		len++;
	}

	if ((int)len > 0 && len < R_BIN_SIZEOF_STRINGS) {
		char *str = calloc (1, len + 1);
		if (str) {
			r_buf_read_at (bin->b, (bin->strings[idx]) + uleblen, (ut8*)str, len);
			str[len] = 0;
			return str;
		}
	}
	
	return NULL;
}


/*
 * Count the number of '1' bits in a word.
 */
static int countOnes(ut32 val) {
	int count = 0;

	val = val - ((val >> 1) & 0x55555555);
	val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
	count = (((val + (val >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;

	return count;
}

/*
 * Flag for use with createAccessFlagStr().
 */
typedef enum {
	kAccessForClass = 0, kAccessForMethod = 1, kAccessForField = 2,
	kAccessForMAX
} AccessFor;

/*
 * Create a new string with human-readable access flags.
 *
 * In the base language the access_flags fields are type u2; in Dalvik
 * they're u4.
 */
static char *createAccessFlagStr(ut32 flags, AccessFor forWhat) {
#define NUM_FLAGS 18
	static const char* kAccessStrings[kAccessForMAX][NUM_FLAGS] = {
		{
			/* class, inner class */
			"PUBLIC",           /* 0x0001 */
			"PRIVATE",          /* 0x0002 */
			"PROTECTED",        /* 0x0004 */
			"STATIC",           /* 0x0008 */
			"FINAL",            /* 0x0010 */
			"?",                /* 0x0020 */
			"?",                /* 0x0040 */
			"?",                /* 0x0080 */
			"?",                /* 0x0100 */
			"INTERFACE",        /* 0x0200 */
			"ABSTRACT",         /* 0x0400 */
			"?",                /* 0x0800 */
			"SYNTHETIC",        /* 0x1000 */
			"ANNOTATION",       /* 0x2000 */
			"ENUM",             /* 0x4000 */
			"?",                /* 0x8000 */
			"VERIFIED",         /* 0x10000 */
			"OPTIMIZED",        /* 0x20000 */
		},
		{
			/* method */
			"PUBLIC",           /* 0x0001 */
			"PRIVATE",          /* 0x0002 */
			"PROTECTED",        /* 0x0004 */
			"STATIC",           /* 0x0008 */
			"FINAL",            /* 0x0010 */
			"SYNCHRONIZED",     /* 0x0020 */
			"BRIDGE",           /* 0x0040 */
			"VARARGS",          /* 0x0080 */
			"NATIVE",           /* 0x0100 */
			"?",                /* 0x0200 */
			"ABSTRACT",         /* 0x0400 */
			"STRICT",           /* 0x0800 */
			"SYNTHETIC",        /* 0x1000 */
			"?",                /* 0x2000 */
			"?",                /* 0x4000 */
			"MIRANDA",          /* 0x8000 */
			"CONSTRUCTOR",      /* 0x10000 */
			"DECLARED_SYNCHRONIZED", /* 0x20000 */
		},
		{
			/* field */
			"PUBLIC",           /* 0x0001 */
			"PRIVATE",          /* 0x0002 */
			"PROTECTED",        /* 0x0004 */
			"STATIC",           /* 0x0008 */
			"FINAL",            /* 0x0010 */
			"?",                /* 0x0020 */
			"VOLATILE",         /* 0x0040 */
			"TRANSIENT",        /* 0x0080 */
			"?",                /* 0x0100 */
			"?",                /* 0x0200 */
			"?",                /* 0x0400 */
			"?",                /* 0x0800 */
			"SYNTHETIC",        /* 0x1000 */
			"?",                /* 0x2000 */
			"ENUM",             /* 0x4000 */
			"?",                /* 0x8000 */
			"?",                /* 0x10000 */
			"?",                /* 0x20000 */
		},
	};
	const int kLongest = 21;        /* strlen of longest string above */
	int i, count;
	char* str;
	char* cp;

	/*
	 * Allocate enough storage to hold the expected number of strings,
	 * plus a space between each.  We over-allocate, using the longest
	 * string above as the base metric.
	 */
	count = countOnes(flags);
	cp = str = (char*) malloc(count * (kLongest+1) +1);
	for (i = 0; i < NUM_FLAGS; i++) {
		if (flags & 0x01) {
			const char* accessStr = kAccessStrings[forWhat][i];
			int len = strlen(accessStr);
			if (cp != str) {
				*cp++ = ' ';
			}
			memcpy(cp, accessStr, len);
			cp += len;
		}
		flags >>= 1;
	}
	*cp = '\0';
	return str;
}


static char *dex_method_signature(RBinDexObj *bin, int method_idx) {
	ut32 proto_id, params_off, type_id, list_size;
	char *r, *return_type = NULL, *signature = NULL, *buff = NULL; 
	ut8 *bufptr;
	ut16 type_idx;
	int pos = 0, i, size = 1;

	if (method_idx < 0 || method_idx >= bin->header.method_size) {
		return NULL;
	}
	proto_id = bin->methods[method_idx].proto_id;
	if (proto_id >= bin->header.prototypes_size) {
		return NULL;
	}
	params_off = bin->protos[proto_id].parameters_off;
	if (params_off  >= bin->size) {
		return NULL;
	}
	type_id = bin->protos[proto_id].return_type_id;
	if (type_id >= bin->header.types_size ) {
		return NULL;
	}
	return_type = getstr (bin, bin->types[type_id].descriptor_id);
	if (!return_type) {
		return NULL;
	}
	if (!params_off) {
		return r_str_newf ("()%s", return_type);;
	}
	bufptr = bin->b->buf;
	list_size = r_read_le32 (bufptr + params_off); // size of the list, in entries
	signature = calloc (0, sizeof (char));
	if (!signature) {
		return NULL;
	}
	// TODO: improve performance on this fucking shit
	// TODO: r_strbuf_append
	//dprintf("Parsing Signature List with %d items\n", list_size);
	for (i = 0; i < list_size; i++) {
		int buff_len = 0;
		if (params_off + 4 + (i*2) >= bin->size) {
			continue;
		}
		type_idx = r_read_le16 (bufptr + params_off + 4 + (i*2));
		if (type_idx < 0 || type_idx >= bin->header.types_size) {
			continue;
		}
		buff = getstr (bin, bin->types[type_idx].descriptor_id);
		if (!buff) {
			continue;
		}
		buff_len = strlen (buff);
		size += buff_len + 1;
		signature = realloc (signature, size);
		strcpy (signature + pos, buff);
		pos += buff_len;
	}
	// TODO: check that
	//free(bufptr);
	free (buff);
	r = r_str_newf ("(%s)%s", signature, return_type);
	free (signature);
	return r;
}

static int check (RBinFile *arch);
static int check_bytes (const ut8 *buf, ut64 length);

static Sdb *get_sdb (RBinObject *o) {
	if (!o || !o->bin_obj) return NULL;
	struct r_bin_dex_obj_t *bin = (struct r_bin_dex_obj_t *) o->bin_obj;
	if (bin->kv) {
		return bin->kv;
	}
	return NULL;
}

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	void *res = NULL;
	RBuffer *tbuf = NULL;
	if (!buf || !sz || sz == UT64_MAX) {
		return NULL;
	}
	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	res = r_bin_dex_new_buf (tbuf);
	r_buf_free (tbuf);
	return res;
}

static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;

	if (!arch || !arch->o) {
		return false;
	}
	arch->o->bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj ? true: false;
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < 8) {
		return false;
	}
	// Non-extended opcode dex file
	if (!memcmp (buf, "dex\n035\0", 8)) {
		return true;
	}
	// Extended (jumnbo) opcode dex file, ICS+ only (sdk level 14+)
	if (!memcmp (buf, "dex\n036\0", 8)) {
		return true;
	}
	// M3 (Nov-Dec 07)
	if (!memcmp (buf, "dex\n009\0", 8)) {
		return true;
	}
	// M5 (Feb-Mar 08)
	if (!memcmp (buf, "dex\n009\0", 8)) {
		return true;
	}
	// Default fall through, should still be a dex file
	if (!memcmp (buf, "dex\n", 4)) {
		return true;
	}
	return false;
}

static RBinInfo *info(RBinFile *arch) {
	RBinHash *h;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = arch->file? strdup (arch->file): NULL;
	ret->type = strdup ("DEX CLASS");
	ret->has_va = false;
	ret->bclass = r_bin_dex_get_version (arch->o->bin_obj);
	ret->rclass = strdup ("class");
	ret->os = strdup ("linux");
	ret->subsystem = strdup ("any");
	ret->machine = strdup ("Dalvik VM");
	h = &ret->sum[0];
	h->type = "sha1";
	h->len = 20;
	h->addr = 12;
	h->from = 12;
	h->to = arch->buf->length-32;
	memcpy (h->buf, arch->buf->buf+12, 20);
	h = &ret->sum[1];
	h->type = "adler32";
	h->len = 4;
	h->addr = 0x8;
	h->from = 12;
	h->to = arch->buf->length-h->from;
	h = &ret->sum[2];
	h->type = 0;
	memcpy (h->buf, arch->buf->buf + 8, 4);
	{
		ut32 *fc = (ut32 *)(arch->buf->buf + 8);
		ut32  cc = __adler32 (arch->buf->buf + 12, arch->buf->length - 12);
		if (*fc != cc) {
			eprintf ("# adler32 checksum doesn't match. Type this to fix it:\n");
			eprintf ("# found 0x%08x   should be 0x%08x\n", *fc, cc);
			eprintf ("wv 0x%08x @ 8\n", cc);
			eprintf ("wx `ph sha1 $s-32 @32` @ 12 ; wx `ph adler32 $s-12 @ 12` @ 8\n");
		}
	}
	ret->arch = strdup ("dalvik");
	ret->lang = "dalvik";
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0; //1 | 4 | 8; /* Stripped | LineNums | Syms */
	return ret;
}

static RList *strings(RBinFile *arch) {
	struct r_bin_dex_obj_t *bin = NULL;
	RBinString *ptr = NULL;
	RList *ret = NULL;
	int i, len;
	ut8 buf[6];
	ut64 off;
	if (!arch || !arch->o) {
		return NULL;
	}
	bin = (struct r_bin_dex_obj_t *) arch->o->bin_obj;
	if (!bin || !bin->strings) {
		return NULL;
	}
	if (bin->header.strings_size > bin->size) {
		bin->strings = NULL;
		return NULL;
	}
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	for (i = 0; i < bin->header.strings_size; i++) {
		if (!(ptr = R_NEW0 (RBinString))) {
			break;
		}
		if (bin->strings[i] > bin->size || bin->strings[i] + 6 > bin->size) {
			goto out_error;
		}
		r_buf_read_at (bin->b, bin->strings[i], (ut8*)&buf, 6);
		len = dex_read_uleb128 (buf);

		if (len > 1 && len < R_BIN_SIZEOF_STRINGS) {
			ptr->string = malloc (len + 1);
			if (!ptr->string) {
				goto out_error;
			}
			off = bin->strings[i] + dex_uleb128_len (buf);
			if (off > bin->size || off + len > bin->size) {
				free (ptr->string);
				goto out_error;
			}
			r_buf_read_at (bin->b, off, (ut8*)ptr->string, len);
			ptr->string[len] = 0;
			ptr->vaddr = ptr->paddr = bin->strings[i];
			ptr->size = len;
			ptr->length = len;
			ptr->ordinal = i+1;
			r_list_append (ret, ptr);
		} else {
			free (ptr);
		}
	}
	return ret;
out_error:
	r_list_free (ret);
	free (ptr);
	return NULL;
}

/*
static char *get_string(RBinDexObj *bin, int cid, int idx) {
	char *c_name, *m_name, *res;
	if (idx < 0 || idx >= bin->header.strings_size) {
		return NULL;
	}
	if (cid < 0 || cid >= bin->header.strings_size) {
		return NULL;
	}
	c_name = getstr (bin, cid);
	m_name = getstr (bin, idx);
	if (c_name && *c_name == ',') {
		res = r_str_newf ("%s", m_name);
	} else {
		if (c_name && m_name) {
			res = r_str_newf ("%s", m_name);
		} else {
			if (c_name && m_name) {
				res = r_str_newf ("unk.%s", c_name);
			} else {
				res = r_str_newf ("UNKNOWN");
			}
		}
	}
	free (c_name);
	free (m_name);
	return res;
}
*/

/* TODO: check boundaries */
static char *dex_method_name(RBinDexObj *bin, int idx) {
	if (idx < 0 || idx >= bin->header.method_size) {
		return NULL;
	}
	int cid = bin->methods[idx].class_id;
	int tid = bin->methods[idx].name_id;
	if (cid < 0 || cid >= bin->header.strings_size) {
		return NULL;
	}
	if (tid < 0 || tid >= bin->header.strings_size) {
		return NULL;
	}
	return getstr (bin, tid);
}

static char *dex_class_name_byid(RBinDexObj *bin, int cid) {
	int tid;
	if (!bin || !bin->types) {
		return NULL;
	}
	if (cid < 0 || cid >= bin->header.types_size) {
		return NULL;
	}
	tid = bin->types[cid].descriptor_id;
	return getstr (bin, tid);
}

static char *dex_field_name(RBinDexObj *bin, int fid) {
	int tid;
	if (!bin || !bin->fields) {
		return NULL;
	}
	if (fid < 0 || fid >= bin->header.fields_size) {
		return NULL;
	}
	tid = bin->fields[fid].class_id;
	if (tid < 0 || tid >= bin->header.types_size) {
		return NULL;
	}
	return getstr (bin, bin->types[tid].descriptor_id);
}

static char *dex_method_fullname(RBinDexObj *bin, int method_idx) {
	if (!bin || !bin->types) {
		return NULL;
	}

	if (method_idx < 0 || method_idx >= bin->header.method_size) {
		return NULL;
	}

	int cid = bin->methods[method_idx].class_id;

	if (cid < 0 || cid >= bin->header.types_size) {
		return NULL;
	}

	char *name = dex_method_name (bin, method_idx);
	char *class_name = dex_class_name_byid (bin, cid);
	class_name = r_str_replace (class_name, ";", "", 0); //TODO: move to func
	char *signature = dex_method_signature (bin, method_idx);
	char *flagname = r_str_newf ("%s.%s%s", class_name, name, signature);
	free (name);
	free (class_name);
	free (signature);
	return flagname;
}

/*
static char *getClassName(const char *name) {
	const char *p;
	if (!name) {
		return NULL;
	}
	p = strstr (name, ".L");
	if (p) {
		char *q, *r = strdup (p + 2);
		q = strchr (r, ';');
		if (q) *q = 0;
		return r;
	}
	return NULL;
}
*/

static char *dex_class_name(RBinDexObj *bin, RBinDexClass *c) {
	int cid, tid;
	if (!bin || !c || !bin->types) {
		return NULL;
	}
	cid = c->class_id;
	if (cid < 0 || cid >= bin->header.types_size) {
		return NULL;
	}
	tid = bin->types[cid].descriptor_id;
	return getstr (bin, tid);
}

// wtf?
static void __r_bin_class_free(RBinClass *p) {
	r_list_free (p->methods);
	r_list_free (p->fields);
	r_bin_class_free (p);
}

static char *dex_class_super_name(RBinDexObj *bin, RBinDexClass *c) {
	int cid, tid;
	if (!bin || !c || !bin->types) {
		return NULL;
	}
	cid = c->super_class;
	if (cid < 0 || cid >= bin->header.types_size) {
		return NULL;
	}
	tid = bin->types[cid].descriptor_id;
	return getstr (bin, tid);
}

static void parse_class(RBinFile *binfile, RBinDexObj *bin, RBinDexClass *c, int class_index, int *methods, int *sym_count) {
	ut64 SF, IF, DM, VM, lastIndex;
	ut8 ff[sizeof (DexField)] = {0};
	ut8 ff2[16] = {0};
	char *class_name, *cln = NULL;
	int total, i;
	const ut8 *p, *p_end;
	DexField field;

	if (!c || !c->class_data_offset) {
		return;
	}

	class_name = dex_class_name (bin, c);
	class_name = r_str_replace (class_name, ";", "", 0); //TODO: move to func

	if (!class_name || !*class_name) {
		return;
	}

	dprintf("  Class descriptor  : '%s'\n", dex_class_name (bin, c));
	dprintf("  Access flags      : 0x%04x (%s)\n", c->access_flags, createAccessFlagStr(c->access_flags, kAccessForClass));
	dprintf("  Superclass        : '%s'\n", dex_class_super_name (bin, c));
	dprintf("  Interfaces        -\n");

	p = r_buf_get_at (binfile->buf, c->class_data_offset, NULL);
	p_end = p + binfile->buf->length - c->class_data_offset;

	/* data header */
	/* walk over class data items */
	p = r_uleb128 (p, p_end - p, &SF);
	p = r_uleb128 (p, p_end - p, &IF);
	p = r_uleb128 (p, p_end - p, &DM);
	p = r_uleb128 (p, p_end - p, &VM);

	/* parsing static and instance fields is known to be:
	 * - slow
	 * - wrong (offset doesnt matches the one expected in the disasm
	 * - i miss some fields.. maybe we need more testing
	 */

	RBinClass *cls = R_NEW0 (RBinClass);
	// get source file name (ClassName.java)
	// TODO: use RConstr here
	//class->name = strdup (name[0]<0x41? name+1: name);
	cls->name = class_name;
	cls->index = class_index;
	cls->addr = c->class_id + bin->header.class_offset;
	cls->methods = r_list_new ();
	//cls->methods->free = free;
	cls->fields = r_list_new ();
	//cls->fields->free = free;
	//class->name = r_str_replace (cn, ";", "", 0);
	r_list_append (bin->classes_list, cls);

	dprintf("  Static fields     -\n");
	/* static fields */
	lastIndex = 0;
	for (i = 0; i < SF; i++) {
		ut64 fieldIndex, accessFlags;
		
		p = r_uleb128 (p, p_end - p, &fieldIndex); // fieldIndex
		p = r_uleb128 (p, p_end - p, &accessFlags); // accessFlags
		fieldIndex += lastIndex;
		total = bin->header.fields_offset + (sizeof (DexField) * fieldIndex);
		if (r_buf_read_at (binfile->buf, total, ff, sizeof (DexField)) != sizeof (DexField)) {
			break;
		}
		field.class_id = r_read_le16 (ff);
		field.type_id = r_read_le16 (ff + 2);
		field.name_id = r_read_le32 (ff + 4);
		char *fieldName = getstr (bin, field.name_id);

		const char* accessStr = createAccessFlagStr(accessFlags, kAccessForField);
		if (field.type_id < 0 || field.type_id >= bin->header.types_size) {
			break;
		}
		int tid = bin->types[field.type_id].descriptor_id;
		const char* type_str = getstr (bin, tid);//get_string(bin, field.type_id, tid);

		if (1) {
			RBinSymbol *sym = R_NEW0 (RBinSymbol);
			/* index matters because two fields can have the same name */
			sym->name = r_str_newf ("%s.sfield_%s:%s", class_name, fieldName, type_str);
			sym->name = r_str_replace (sym->name, "method.", "", 0);
			sym->name = r_str_replace (sym->name, ";", "", 0);
			sym->type = r_str_const ("STATIC");
			sym->paddr = sym->vaddr = total;
			sym->ordinal = (*sym_count)++;
			
			dprintf("    #%d              : (in %s)\n", i, class_name);
			dprintf("      name          : '%s'\n", fieldName);
			dprintf("      type          : '%s'\n", type_str);
			dprintf("      access        : 0x%04x (%s)\n", (unsigned int)accessFlags, accessStr);

			r_list_append (bin->methods_list, sym);
			r_list_append (cls->fields, sym);
		}
		lastIndex = fieldIndex;
	}

	dprintf("  Instance fields   -\n");
	/* instance fields */
	lastIndex = 0;
	for (i = 0; i < IF; i++) {
		DexField field;
		ut64 fieldIndex, accessFlags;
		// int fieldOffset = bin->header.fields_offset + (p - op);
		p = r_uleb128 (p, p_end - p, &fieldIndex); // fieldIndex
		p = r_uleb128 (p, p_end - p, &accessFlags); // accessFlags
		fieldIndex += lastIndex;
		total = bin->header.fields_offset + (sizeof (DexField) * fieldIndex);
		if ((int)fieldIndex < 0) {
			eprintf ("Invalid field index %d\n", (int)fieldIndex);
			continue;
		}
		if (r_buf_read_at (binfile->buf, bin->header.fields_offset +
				fieldIndex * sizeof (DexField), ff, sizeof (DexField)) != sizeof (DexField)) {
			break;
		}
		field.class_id = r_read_le16 (ff);
		field.type_id = r_read_le16 (ff + 2);
		field.name_id = r_read_le32 (ff + 4);
		char *name = getstr (bin, field.name_id);
		cln = r_str_replace (strdup (class_name), "method.", "", 0);
		cln = r_str_replace (cln, ";", "_", 0);


		const char* accessStr = createAccessFlagStr(accessFlags, kAccessForField);
		if (field.type_id < 0 || field.type_id >= bin->header.types_size) {
			break;
		}
		int tid = bin->types[field.type_id].descriptor_id;
		const char* type_str = getstr (bin, tid);

		if (1) {
			RBinSymbol *sym = R_NEW0 (RBinSymbol);
			sym->name = r_str_newf ("%s.ifield_%s:%s", class_name, name, type_str);
			sym->name = r_str_replace (sym->name, "method.", "", 0);
			sym->name = r_str_replace (sym->name, ";", "", 0);
			sym->type = r_str_const ("FIELD");
			sym->paddr = sym->vaddr = total;
			sym->ordinal = (*sym_count)++;

			dprintf("    #%d              : (in %s)\n", i, class_name);
			dprintf("      name          : '%s'\n", name);
			dprintf("      type          : '%s'\n", type_str);
			dprintf("      access        : 0x%04x (%s)\n", (unsigned int)accessFlags, accessStr);

			r_list_append (bin->methods_list, sym);
			r_list_append (cls->fields, sym);
		}
		lastIndex = fieldIndex;
	}

	dprintf ("  Direct methods    -\n");
	/* direct methods (aka static) */
	ut64 omi = 0;
	for (i = 0; i < DM; i++) {
		char *method_name, *flag_name;
		ut64 MI, MA, MC;
		p = r_uleb128 (p, p_end - p, &MI);
		MI += omi;
		omi = MI;
		// the mi is diff
#if 0
		index into the method_ids list for the identity of this method (includes the name and descriptor), represented as a difference from the index of previous element in the list. The index of the first element in a list is represented directly.
#endif
		p = r_uleb128 (p, p_end - p, &MA);
		p = r_uleb128 (p, p_end - p, &MC);

		// TODO: MOVE CHECKS OUTSIDE!
		if (MI<bin->header.method_size) {
			if (methods) {
				methods[MI] = 1;
			}
		}

		method_name = dex_method_name (bin, MI);
		char *signature = dex_method_signature(bin, MI);
		
		if (!method_name) {
			method_name = strdup ("unknown");
		}

		flag_name = r_str_newf ("%s.method.%s%s", class_name, method_name, signature);

		if (!flag_name) {
			continue;
		}

		const char* accessStr = createAccessFlagStr(MA, kAccessForMethod);

		dprintf("    #%d              : (in %s)\n", i, class_name);
		dprintf("      name          : '%s'\n", method_name);
		dprintf("      type          : '%s'\n", signature);
		dprintf("      access        : 0x%04x (%s)\n", (unsigned int)MA, accessStr);

		/* add symbol */
		if (*flag_name) {
			RBinSymbol *sym = R_NEW0 (RBinSymbol);
			sym->name = flag_name;
			sym->type = r_str_const ("FUNC");
			sym->bind = r_str_const ("GLOBAL");
			sym->paddr = MC;// + 0x10;
			sym->vaddr = MC;// + 0x10;
			sym->ordinal = (*sym_count)++;
			if (MC > 0) {
				 /* avoid methods at 0 paddr */
#if 0
				// TODO: use sdb+pf to show method header
				ut16 regsz;
				ut16 ins_size
				ut16 outs_size
				ut16 tries_size
				ut32 debug_info_off
				ut32 insns_size
				ut16[insn_size] insns;
				ut16 padding = 0
				try_item[tries_size] tries
				encoded_catch_handler_list handlers
#endif

				// TODO: parse debug info
				if (r_buf_read_at (binfile->buf, binfile->buf->base + MC, ff2, 16) < 1) {
					free (sym);
					continue;
				}
				//ut16 regsz = r_read_le16 (ff2);
				//ut16 ins_size = r_read_le16 (ff2 + 2);
				//ut16 outs_size = r_read_le16 (ff2 + 4);
				ut16 tries_size = r_read_le16 (ff2 + 6);
				//ut32 debug_info_off = r_read_le32 (ff2 + 8);
				ut32 insns_size = r_read_le32 (ff2 + 12);

				ut64 prolog_size = 2 + 2 + 2 + 2 + 4 + 4;
				if (tries_size > 0) {
					//prolog_size += 2 + 8*tries_size; // we need to parse all so the catch info...
				}
				// TODO: prolog_size
				sym->paddr = MC + prolog_size;// + 0x10;
				sym->vaddr = MC + prolog_size;// + 0x10;
				sym->size = insns_size * 2;
				//eprintf("%s (0x%x-0x%x) size=%d\nregsz=%d\ninsns_size=%d\nouts_size=%d\ntries_size=%d\ninsns_size=%d\n", flag_name, sym->vaddr, sym->vaddr+sym->size, prolog_size, regsz, ins_size, outs_size, tries_size, insns_size);
				r_list_append (bin->methods_list, sym);
				r_list_append (cls->methods, sym);

				if (bin->code_from > sym->paddr) {
					bin->code_from = sym->paddr;
				}
				if (bin->code_to < sym->paddr) {
					bin->code_to = sym->paddr;
				}

				/* cache in sdb */
				if (!mdb) {
					mdb = sdb_new0 ();
				}
				sdb_num_set (mdb, sdb_fmt (0, "method.%d", MI), sym->paddr, 0);
			} else {
				//r_list_append (bin->methods_list, sym);
				// XXX memleak sym
				free (sym);
			}
		} else {
			free (flag_name);
		}
		free (method_name);
	}

	/* virtual methods */
	dprintf ("  Virtual methods   -\n");
	omi = 0;
	for (i = 0; i < VM; i++) {
		ut64 MI, MA, MC;
		p = r_uleb128 (p, p_end-p, &MI);
		p = r_uleb128 (p, p_end-p, &MA);
		p = r_uleb128 (p, p_end-p, &MC);

		// TODO: offset from the start of the file to the code structure for this method, 
		// or 0 if this method is either abstract or native. The offset should be to a 
		// location in the data section. The format of the data is specified by "code_item" below.

		MI += omi;
		omi = MI;

		// TODO: MOVE CHECKS OUTSIDE!
		if ((int)MI >= 0 && MI < bin->header.method_size) {
			if (methods) {
				methods[MI] = 1;
			}
		}

		char *name = dex_method_name (bin, MI);
		char *signature = dex_method_signature(bin, MI);

		const char* accessStr = createAccessFlagStr(MA, kAccessForMethod);

		dprintf("    #%d              : (in %s)\n", i, class_name);
		dprintf("      name          : '%s'\n", name);
		dprintf("      type          : '%s'\n", signature);
		dprintf("      access        : 0x%04x (%s)\n", (unsigned int)MA, accessStr);

		{
			RBinSymbol *sym = R_NEW0 (RBinSymbol);
			//sym->name = r_str_newf ("virtual.%s.%s", class_name, name);
			sym->name = r_str_newf ("%s.method.%s%s", class_name, name, signature);
			//sym->name = r_str_replace (sym->name, "method.", "", 0);
			//sym->name = r_str_replace (sym->name, ";", "", 0); // TODO: fix ; after method name
			sym->type = r_str_const ("METH");
			sym->bind = r_str_const ("GLOBAL");
			sym->paddr = sym->vaddr = MC + 0x10;
			sym->ordinal = (*sym_count)++;
			r_list_append (bin->methods_list, sym);
			r_list_append (cls->methods, sym);

			if (bin->code_from > sym->paddr) {
				bin->code_from = sym->paddr;
			}
			if (bin->code_to < sym->paddr) {
				bin->code_to = sym->paddr;
			}

		}
		free (name);
		free(signature);
	}
	// TODO:!!!!
	// FIX: FREE BEFORE ALLOCATE!!!
	//free (class_name);
}



static int dex_loadcode(RBinFile *arch, RBinDexObj *bin) {
	int i;
	int *methods = NULL;
	int sym_count = 0;

	// doublecheck??
	if (!bin || bin->methods_list) {
		return false;
	}
	bin->code_from = UT64_MAX;
	bin->code_to = 0;
	bin->methods_list = r_list_new ();
	bin->methods_list->free = free;
	bin->imports_list = r_list_new ();
	bin->imports_list->free = free;
	bin->classes_list = r_list_new ();
	bin->classes_list->free = (RListFree)__r_bin_class_free;

	if (bin->header.method_size>bin->size) {
		bin->header.method_size = 0;
		return false;
	}

	/* WrapDown the header sizes to avoid huge allocations */
	bin->header.method_size = R_MIN (bin->header.method_size, bin->size);
	bin->header.class_size = R_MIN (bin->header.class_size, bin->size);
	bin->header.strings_size = R_MIN (bin->header.strings_size, bin->size);

	if (bin->header.strings_size > bin->size) {
		eprintf ("Invalid strings size\n");
		return false;
	}

	/* debug prototypes */
	/*
	for (i = 0; i < bin->header.prototypes_size; i++) {
		dprintf("PROTO[%d], %d, %d, %d\n", i, bin->protos[i].shorty_id, bin->protos[i].return_type_id, bin->protos[i].parameters_off );
	}
	*/
	

	/* debug strings */
	/*
	for (i = 0; i < bin->header.strings_size; i++) {
		dprintf("STR[%d], %s\n", i, getstr(bin, i));
	}
	*/
	

	if (bin->classes) {
		methods = calloc (sizeof (int), bin->header.method_size);
		for (i = 0; i < bin->header.class_size; i++) {
			char *super_name, *class_name;
			struct dex_class_t *c = &bin->classes[i];
			class_name = dex_class_name (bin, c);
			super_name = dex_class_super_name (bin, c);
			dprintf("Class #%d            -\n", i); // TODO: rename this to idx
			parse_class (arch, bin, c, i, methods, &sym_count);
			free (class_name);
			free (super_name);
		}
	}

	if (methods) {
		//dprintf ("imports: \n");
		int import_count = 0;
		int sym_count = bin->methods_list->length;
		for (i = 0; i < bin->header.method_size; i++) {
			int len = 0;
			if (methods[i]) {
				continue;
			}
			// TODO: move to a function
			if (bin->methods[i].class_id > bin->header.types_size - 1) {
				continue;
			}

			char *class_name = getstr (bin, bin->types[bin->methods[i].class_id].descriptor_id);
			if (!class_name) {
				free (class_name);
				continue;
			}
			len = strlen(class_name);
			if (len < 1) {
				continue;
			}
			class_name[len-1] = 0; // remove last char ";"
			char *method_name = dex_method_name (bin, i);
			char *signature = dex_method_signature (bin, i);
			if (method_name && *method_name) {
				RBinImport *imp = R_NEW0 (RBinImport);
				imp->name  = r_str_newf ("%s.method.%s%s", class_name, method_name, signature);
				imp->type = r_str_const ("FUNC");
				imp->bind = r_str_const ("NONE");
				imp->ordinal = import_count++;
				r_list_append (bin->imports_list, imp);

				RBinSymbol *sym = R_NEW0 (RBinSymbol);
				sym->name = r_str_newf ("imp.%s", imp->name);
				sym->type = r_str_const ("FUNC");
				sym->bind = r_str_const ("NONE");
				sym->paddr = sym->vaddr = bin->b->base + bin->header.header_size 
					+ bin->header.strings_size + bin->header.class_size + 
					(sizeof (struct dex_method_t) * i) ;
				sym->ordinal = sym_count++;
				r_list_append (bin->methods_list, sym);
				sdb_num_set (mdb, sdb_fmt (0, "method.%d", i), sym->paddr, 0);
			}
			free (method_name);
			free (signature);
			free (class_name);
		}
		free (methods);
	}
	return true;
}

static RList* imports(RBinFile *arch) {
	RBinDexObj *bin = (RBinDexObj*) arch->o->bin_obj;
	if (!bin) {
		return NULL;
	}
	if (bin && bin->imports_list) {
		return bin->imports_list;
	}
	dex_loadcode (arch, bin);
	return bin->imports_list;
#if 0
	struct r_bin_dex_obj_t *bin = (struct r_bin_dex_obj_t *) arch->o->bin_obj;
	int i;
	RList *ret = NULL;
	RBinImport *ptr;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	dprintf ("Importing %d methods... \n", bin->header.method_size);
	for (i = 0; i<bin->header.method_size; i++) {
		if (!(ptr = R_NEW (RBinImport)))
			break;
		char *methodname = get_string (bin, bin->methods[i].name_id);
		char *classname = get_string (bin, bin->methods[i].class_id);
		//char *typename = get_string (bin, bin->methods[i].type_id);
dprintf ("----> %d\n", bin->methods[i].name_id);

		if (!methodname) {
			dprintf ("string index out of range\n");
			break;
		}
		snprintf (ptr->name, sizeof (ptr->name), "import.%s.%s",
				classname, methodname);
		ptr->ordinal = i+1;
		ptr->size = 0;
		ptr->vaddr = ptr->offset = getmethodoffset (bin,
			(int)ptr->ordinal, (ut32*)&ptr->size);
dprintf ("____%s__%s____  (%d)  %llx\n", classname,
	methodname, bin->methods[i].name_id, ptr->vaddr);
free (classname);
free (methodname);
		//strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		if (ptr->vaddr) {
			free (ptr);
			continue;
		}
		strncpy (ptr->type, "IMPORT", R_BIN_SIZEOF_STRINGS);
		r_list_append (ret, ptr);
	}
	dprintf ("Done\n");
	return ret;
#endif
}

static RList *methods(RBinFile *arch) {
	RBinDexObj *bin;
	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	bin = (RBinDexObj*) arch->o->bin_obj;
	if (!bin->methods_list) {
		dex_loadcode (arch, bin);
	}
	return bin->methods_list;
}

static RList *classes(RBinFile *arch) {
	RBinDexObj *bin;
	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	bin = (RBinDexObj*) arch->o->bin_obj;
	if (!bin->classes_list) {
		dex_loadcode (arch, bin);
	}
	return bin->classes_list;
/*
	struct r_bin_dex_obj_t *bin;
	struct dex_class_t entry;
	int i, class_index = 0;
	RList *ret = NULL;
	RBinClass *class;
	char name[128];

	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	bin = (struct r_bin_dex_obj_t *) arch->o->bin_obj;
	if (bin->header.class_size > bin->size) {
		eprintf ("Too many classes %d\n", bin->header.class_size);
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = (RListFree)__r_bin_class_free;
	for (i = 0; i < bin->header.class_size; i++) {
		ut64 class_addr = (ut64) bin->header.class_offset \
			+ (sizeof (struct dex_class_t)*i);
#if 0 // Wrong old method - reading bytes direct into struct at some offset
		// ETOOSLOW
		r_buf_read_at (bin->b, class_addr, (ut8*)&entry,
			sizeof (struct dex_class_t));
#endif
		ut8 cls[sizeof (struct dex_class_t)] = {0};
		r_buf_read_at (bin->b, class_addr, cls, sizeof (struct dex_class_t));
		entry.class_id = r_read_le32 (cls + 0);
		entry.access_flags = r_read_le32 (cls + 4);
		entry.super_class = r_read_le32 (cls + 8);
		entry.interfaces_offset = r_read_le32 (cls + 12);
		entry.source_file = r_read_le32 (cls + 16);
		entry.anotations_offset = r_read_le32 (cls + 20);
		entry.class_data_offset = r_read_le32 (cls + 24);
		entry.static_values_offset = r_read_le32 (cls + 28);
		
		// TODO: implement sections.. each section specifies a class boundary
		// lazy check
		if (!bin->strings) {
			// no bin->strings found
			break;
		}
		if (entry.source_file >= bin->size) {
			continue;
		}
		// unsigned if (entry.source_file<0 || entry.source_file >= bin->header.strings_size)
		if (entry.source_file >= bin->header.strings_size) {
			continue;
		}
		if (bin->strings[entry.source_file] > bin->size) {
			continue;
		}
		r_buf_read_at (bin->b, bin->strings[entry.source_file], (ut8*)name, sizeof (name));
		//snprintf (ptr->name, sizeof (ptr->name), "field.%s.%d", name, i);
		class = R_NEW0 (RBinClass);
		// get source file name (ClassName.java)
		// TODO: use RConstr here
		//class->name = strdup (name[0]<0x41? name+1: name);
		class->name = dex_class_name_byid (bin, entry.class_id);
		// find reference to this class instance
		char *cn = dex_class_name (bin, &entry);
		if (cn) {
			free (class->name);
			class->index = class_index++;
			class->addr = entry.class_id + bin->header.class_offset;
			class->name = r_str_replace (cn, ";", "", 0);
			//class->addr = class_addr;

			// FIX: THIS IS REDUNDANT AND DUPLICATES SYMBOLS
			//parse_class (arch, bin, &entry, class, NULL);

			r_list_append (ret, class);

		} else {
			dprintf("INVALID CLASS NAME");
			free (class->name);
			free (class);
		}
	}
	return ret;
	*/
}

static int already_entry(RList *entries, ut64 vaddr) {
	RBinAddr *e;
	RListIter *iter;
	r_list_foreach (entries, iter, e) {
		if (e->vaddr == vaddr)
			return 1;
	}
	return 0;
}

static RList *entries(RBinFile *arch) {
	RListIter *iter;
	RBinDexObj *bin;
	RBinSymbol *m;
	RBinAddr *ptr;
	RList *ret;

	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	bin = (RBinDexObj*) arch->o->bin_obj;
	ret = r_list_new ();

	if (!bin->methods_list) {
		dex_loadcode (arch, bin);
	}
#if 1
	// TODO: entry point in dalvik? WTF!
	// XXX: entry + main???
	r_list_foreach (bin->methods_list, iter, m) {
		// LOOKING FOR ".method.main([Ljava/lang/String;)V"
		if (strlen (m->name) > 26 && !strcmp (m->name + strlen (m->name) - 27, ".main([Ljava/lang/String;)V")) {
			//dprintf ("ENTRY -> %s\n", m->name);
			if (!already_entry (ret, m->paddr)) {
				if ((ptr = R_NEW0 (RBinAddr))) {
					ptr->paddr = ptr->vaddr = m->paddr;
					r_list_append (ret, ptr);
				}
			}
		}
	}
#endif
	if (r_list_empty (ret)) {
		if (!already_entry (ret, bin->code_from)) {
			ptr = R_NEW0 (RBinAddr);
			if (ptr) {
				ptr->paddr = ptr->vaddr = bin->code_from;
				r_list_append (ret, ptr);
			}
		}
	}
	return ret;
}

static ut64 offset_of_method_idx(RBinFile *arch, struct r_bin_dex_obj_t *dex, int idx) {
	int off = dex->header.method_offset + idx;
	//(sizeof (struct dex_method_t)*idx);
	//const char *name = dex_method_name (dex, idx);
	//eprintf ("idx=%d off=%d (%s)\n", idx, off, name);
	//off = sdb_num_get (mdb, name, NULL);
	off = sdb_num_get (mdb, sdb_fmt (0, "method.%d", idx), 0);
	//p = r_uleb128 (p, p_end-p, &MI);
	// READ CODE
	return off;
}

//TODO must return ut64 imho
static int getoffset(RBinFile *arch, int type, int idx) {
	struct r_bin_dex_obj_t *dex = arch->o->bin_obj;
	switch (type) {
	case 'm': // methods
		// TODO: ADD CHECK
		return offset_of_method_idx (arch, dex, idx);
	case 'o': // objects
		break;
	case 's': // strings
		if (dex->header.strings_size > idx) {
			if (dex->strings) return dex->strings[idx];
		}
		break;
	case 't': // things
		break;
	}
	return -1;
}

static char *getname(RBinFile *arch, int type, int idx) {
	struct r_bin_dex_obj_t *dex = arch->o->bin_obj;
	switch (type) {
	case 'm': // methods
		return dex_method_fullname (dex, idx);
	case 'c': // classes
		return dex_class_name_byid (dex, idx);
	case 'f': // fields
		return dex_field_name (dex, idx);
	}
	return NULL;
}

static RList *sections(RBinFile *arch) {
	struct r_bin_dex_obj_t *bin = arch->o->bin_obj;
	RList *ml = methods (arch);
	RBinSection *ptr = NULL;
	int ns, fsymsz = 0;
	RList *ret = NULL;
	RListIter *iter;
	RBinSymbol *m;
	int fsym = 0;

	r_list_foreach (ml, iter, m) {
		if (!fsym || m->paddr < fsym) {
			fsym = m->paddr;
		}
		ns = m->paddr + m->size;
		if (ns > arch->buf->length) {
			continue;
		}
		if (ns > fsymsz) {
			fsymsz = ns;
		}
	}
	if (!fsym) {
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;

	if ((ptr = R_NEW0 (RBinSection))) {
		strcpy (ptr->name, "header");
		ptr->size = ptr->vsize = sizeof (struct dex_header_t);
		ptr->paddr= ptr->vaddr = 0;
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP;
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	if ((ptr = R_NEW0 (RBinSection))) {
		strcpy (ptr->name, "constpool");
		//ptr->size = ptr->vsize = fsym;
		ptr->paddr= ptr->vaddr = sizeof (struct dex_header_t);
		ptr->size = bin->code_from - ptr->vaddr; // fix size
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP;
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	if ((ptr = R_NEW0 (RBinSection))) {
		strcpy (ptr->name, "code");
		ptr->vaddr = ptr->paddr = bin->code_from; //ptr->vaddr = fsym;
		ptr->size = bin->code_to - ptr->paddr;
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	if ((ptr = R_NEW0 (RBinSection))) {
		//ut64 sz = arch ? r_buf_size (arch->buf): 0;
		strcpy (ptr->name, "data");
		ptr->paddr = ptr->vaddr = fsymsz+fsym;
		if (ptr->vaddr > arch->buf->length) {
			ptr->paddr = ptr->vaddr = bin->code_to;
			ptr->size = ptr->vsize = arch->buf->length - ptr->vaddr;
		} else {
			ptr->size = ptr->vsize = arch->buf->length - ptr->vaddr;
			// hacky workaround
			//dprintf ("Hack\n");
			//ptr->size = ptr->vsize = 1024;
		}
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP; //|2;
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	return ret;
}

static ut64 size(RBinFile *arch) {
	int ret;
	ut32 off = 0, len = 0;
	ut8 u32s[sizeof (ut32)] = {0};

	ret = r_buf_read_at (arch->buf, 108, u32s, 4);
	if (ret != 4) {
		return 0;
	}
	off = r_read_le32 (u32s);
	ret = r_buf_read_at (arch->buf, 104, u32s, 4);
	if (ret != 4) {
		return 0;
	}
	len = r_read_le32 (u32s);
	return off + len;
}

RBinPlugin r_bin_plugin_dex = {
	.name = "dex",
	.desc = "dex format bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.entries = entries,
	.classes = classes,
	.sections = sections,
	.symbols = methods,
	.imports = imports,
	.strings = strings,
	.info = &info,
	.size = &size,
	.get_offset = &getoffset,
	.get_name = &getname
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dex,
	.version = R2_VERSION
};
#endif
