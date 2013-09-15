/* radare - LGPL - Copyright 2011-2013 - pancake */

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

static int load(RBinArch *arch) {
	arch->bin_obj = r_bin_dex_new_buf (arch->buf);
	return arch->bin_obj ? R_TRUE: R_FALSE;
}

static ut64 baddr(RBinArch *arch) {
	return 0;
}

static char *flagname (const char *class, const char *method) {
	char *p, *str, *s = malloc (strlen (class) + strlen (method)+2);
	str = s;
	p = (char*)r_str_lchr (class, '$');
	if (!p) p = (char *)r_str_lchr (class, '/');
//eprintf ("D=%d (%s)\n", p, p?p:".");
	p = (char*)r_str_rchr (class, p, '/');
#if 1
	//if (!p) p = class; else p--;
//if (p) p = r_str_lchr (p, '/');
//eprintf ("P=%d\n", p);
#if 0
	if (!p) {
		char *q = r_str_lchr (p-1, '/');
		if (q) p = q;
	}
#endif
	if (p) class = p+1;
#endif
//eprintf ("NAME (%s)\n", class);
	for (str=s; *class; class++) {
		switch (*class) {
		case '$':
		case '/': *s++ = '_'; break;
		case ';': *s++ = '.'; break;
		default: *s++ = *class; break;
		}
	}
	for (*s++='.'; *method; method++) {
		switch (*method) {
		case '<': case '>':
		case '/': *s++ = '_'; break;
		case ';': *s++ = '.'; break;
		default: *s++ = *method; break;
		}
	}
	*s = 0;
	return str;
}

static int check(RBinArch *arch) {
	if (!arch->buf || !arch->buf->buf)
		return R_FALSE;
	// Non-extended opcode dex file
	if (!memcmp (arch->buf->buf, "dex\n035\0", 8))
	        return R_TRUE;
	// Extended (jumnbo) opcode dex file, ICS+ only (sdk level 14+)
	if (!memcmp (arch->buf->buf, "dex\n036\0", 8))
	        return R_TRUE;
	// M3 (Nov-Dec 07)
	if (!memcmp (arch->buf->buf, "dex\n009\0", 8))
	        return R_TRUE;
	// M5 (Feb-Mar 08)
        if (!memcmp (arch->buf->buf, "dex\n009\0", 8))
	        return R_TRUE;
	// Default fall through, should still be a dex file
	if (!memcmp (arch->buf->buf, "dex\n", 4))
                return R_TRUE;
	return R_FALSE;
}

static RBinInfo *info(RBinArch *arch) {
	char *version;
	RBinHash *h;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) return NULL;
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->type, "DEX CLASS", R_BIN_SIZEOF_STRINGS);
	ret->has_va = R_FALSE;
	version = r_bin_dex_get_version (arch->bin_obj);
	strncpy (ret->bclass, version, R_BIN_SIZEOF_STRINGS);
	free (version);
	strncpy (ret->rclass, "class", R_BIN_SIZEOF_STRINGS);
	strcpy (ret->os, "linux");
	strcpy (ret->subsystem, "any");
	strcpy (ret->machine, "Dalvik VM");

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
	memcpy (h->buf, arch->buf->buf+8, 4);
	{
		ut32 *fc = (ut32 *)(arch->buf->buf + 8);
		ut32  cc = __adler32 (arch->buf->buf + h->from, h->to);
		//ut8 *fb = (ut8*)fc, *cb = (ut8*)&cc;
		if (*fc != cc) {
			dprintf ("# adler32 checksum doesn't match. Type this to fix it:\n");
			dprintf ("wx `#sha1 $s-32 @32` @12 ; wx `#adler32 $s-12 @12` @8\n");
		}
	}

	strcpy (ret->arch, "dalvik");
	ret->lang = "java";
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0; //1 | 4 | 8; /* Stripped | LineNums | Syms */
	return ret;
}

static RList* strings (RBinArch *arch) {
	struct r_bin_dex_obj_t *bin = (struct r_bin_dex_obj_t *) arch->bin_obj;
	RBinString *ptr = NULL;
	RList *ret = NULL;
	int i, len;
	ut8 buf[6];

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	for (i = 0; i < bin->header.strings_size; i++) {
		if (!(ptr = R_NEW (RBinString)))
			break;
		r_buf_read_at (bin->b, bin->strings[i], (ut8*)&buf, 6);
		len = dex_read_uleb128 (buf);
		if (len>0 && len < R_BIN_SIZEOF_STRINGS) {
			r_buf_read_at (bin->b, bin->strings[i]+dex_uleb128_len (buf),
					(ut8*)&ptr->string, len);
			ptr->string[(int) len+1]='\0';
			ptr->rva = ptr->offset = bin->strings[i];
			ptr->size = len;
			ptr->ordinal = i+1;
			r_list_append (ret, ptr);
		} //else dprintf ("dex_read_uleb128: invalid read\n");
	}
	return ret;
}

static inline ut32 getmethodoffset (struct r_bin_dex_obj_t *bin, int n, ut32 *size) {
	ut8 *buf, *map_end, *map;
	ut32 mapsz, off = 0L;
	int left;
	*size = 0;
	map = buf = r_buf_get_at (bin->b, bin->header.data_offset, &left);
	if (!map) return 0;
	for (map_end = map+bin->header.data_size; map<map_end;) {
		int num = map[0] + (map[1]<<8);
		int ninsn = map[12] + (map[13]<<8);
		map += 16; // skip header
		mapsz = ninsn%2? (ninsn+1)*2: ninsn*2;
		if (n == num) {
			*size = mapsz;
			off = bin->header.data_offset + (size_t)(map - buf);
			break;
		}
		map += mapsz;
	}
	return off;
}

static char *get_string (struct r_bin_dex_obj_t *bin, int idx) {
	const ut8 buf[128], *buf2;
	int len, uleblen;
	r_buf_read_at (bin->b, bin->strings[idx], (ut8*)&buf, 8);
	len = dex_read_uleb128 (buf);
	buf2 = r_uleb128 (buf, (ut32*) &len);
	uleblen = (size_t)(buf2 - buf);
	// XXX what about 0 length strings?
	if (len>0 && len < R_BIN_SIZEOF_STRINGS) {
		char *str = malloc (len+1);
		if (!str) return NULL;
		r_buf_read_at (bin->b, (bin->strings[idx])+uleblen,
				(ut8*)str, len+uleblen);
		str[len] = 0;
		return str;
	}
	return NULL;
}

/* TODO: check boundaries */
static char *dex_method_name (RBinDexObj *bin, int idx) {
	int tid;
	if (idx<0 || idx>bin->header.method_size)
		return NULL;
	tid = bin->methods[idx].name_id;
	if (tid<0 || tid>bin->header.strings_size)
		return NULL;
	return get_string (bin, tid);
}

static char *dex_class_name (RBinDexObj *bin, RBinDexClass *c) {
	int cid = c->class_id;
	int tid = bin->types [cid].descriptor_id;
	//int sid = bin->strings[tid];
	return get_string (bin, tid);
}

static char *dex_class_super_name (RBinDexObj *bin, RBinDexClass *c) {
	int cid = c->super_class;
	int tid = bin->types [cid].descriptor_id;
	//int sid = bin->strings[tid];
	return get_string (bin, tid);
}


static int dex_loadcode(RBinArch *arch, RBinDexObj *bin) {
	int *methods;
	int i, j;
	char *name;
	const ut8 *p;

	// doublecheck??
	if (bin->methods_list)
		return R_FALSE;
	bin->code_from = UT64_MAX;
	bin->code_to = 0;
	bin->methods_list = r_list_new ();
	bin->methods_list->free = free;
	bin->imports_list = r_list_new ();
	bin->imports_list->free = free;

	methods = malloc (sizeof (int) * bin->header.method_size);
	for (i=0;i<bin->header.method_size;i++) { methods[i] = 0; }

	dprintf ("Walking %d classes\n", bin->header.class_size);
	for (i=0; i<bin->header.class_size; i++) {
		struct dex_class_t *c = &bin->classes[i];
		char *super_name = dex_class_super_name (bin, c);
		char *class_name = dex_class_name (bin, c);
		dprintf ("{\n");
		dprintf ("  class: %d,\n", c->class_id); // indexed by ordinal
		dprintf ("  super: \"%s\",\n", super_name); // indexed by name
		dprintf ("  name: \"%s\",\n", class_name);
		dprintf ("  methods: [\n");
// sdb_queryf ("(-1)classes=%s", class_name)
// sdb_queryf ("class.%s.super=%s", super_name)
// sdb_queryf ("class.%s.methods=%d", class_name, DM);
		p = r_buf_get_at (arch->buf, c->class_data_offset, NULL);
		/* data header */
		{
			ut32 SF, IF, DM, VM;
			p = r_uleb128 (p, &SF);
			p = r_uleb128 (p, &IF);
			p = r_uleb128 (p, &DM);
			p = r_uleb128 (p, &VM);
			dprintf ("  static fields: %d\n", SF);
			/* static fields */
			for (j=0; j<SF; j++) {
				ut32 FI, FA;
				p = r_uleb128 (p, &FI);
				p = r_uleb128 (p, &FA);
				dprintf ("    field_idx: %d\n", FI);
				dprintf ("    field access_flags: %d\n", FA);
			}
			/* instance fields */
			dprintf ("  instance fields: %d\n", IF);
			for (j=0; j<IF; j++) {
				ut32 FI, FA;
				p = r_uleb128 (p, &FI);
				p = r_uleb128 (p, &FA);
				dprintf ("    field_idx: %d,\n", FI);
				dprintf ("    field access_flags: %d,\n", FA);
			}
			/* direct methods */
			dprintf ("  direct methods: %d\n", DM);
			for (j=0; j<DM; j++) {
				char *method_name, *flag_name;
				ut32 MI, MA, MC;
				p = r_uleb128 (p, &MI);
				p = r_uleb128 (p, &MA);
				p = r_uleb128 (p, &MC);

				if (MI<bin->header.method_size) methods[MI] = 1;
				if (MC>0 && bin->code_from>MC) bin->code_from = MC;
				if (MC>0 && bin->code_to<MC) bin->code_to = MC;

				method_name = dex_method_name (bin, MI);
				dprintf ("METHOD NAME %d\n", MI);
				if (!method_name) method_name = strdup ("unknown");
				flag_name = flagname (class_name, method_name);
				dprintf ("f %s @ 0x%x\n", flag_name, MC);
				dprintf ("    { name: %s,\n", method_name);
				dprintf ("      idx: %d,\n", MI);
				dprintf ("      access_flags: 0x%x,\n", MA);
				dprintf ("      code_offset: 0x%x },\n", MC);
				/* add symbol */
				{
					RBinSymbol *sym = R_NEW0 (RBinSymbol);
					strncpy (sym->name, flag_name, R_BIN_SIZEOF_STRINGS);
					strcpy (sym->type, "FUNC");
					sym->offset = sym->rva = MC;
					r_list_append (bin->methods_list, sym);
				}
				free (method_name);
				free (flag_name);
			}
			/* virtual methods */
			dprintf ("  virtual methods: %d\n", VM);
			for (j=0; j<VM; j++) {
				ut32 MI, MA, MC;
				p = r_uleb128 (p, &MI);
				p = r_uleb128 (p, &MA);
				p = r_uleb128 (p, &MC);

				if (MI<bin->header.method_size) methods[MI] = 1;
				if (bin->code_from>MC) bin->code_from = MC;
				if (bin->code_to<MC) bin->code_to = MC;

				name = dex_method_name (bin, MI);
				dprintf ("    method name: %s\n", name);
				dprintf ("    method_idx: %d\n", MI);
				dprintf ("    method access_flags: %d\n", MA);
				dprintf ("    method code_offset: %d\n", MC);
				free (name);
			}
		}
		dprintf ("  ],\n");
		dprintf ("},");
		free (class_name);
		free (super_name);
	}
	dprintf ("imports: \n");
	for (i = 0; i<bin->header.method_size; i++) {
		//RBinDexMethod *method = &bin->methods[i];
		if (!methods[i]) {
			char *method_name = dex_method_name (bin, i);
			dprintf ("import %d (%s)\n", i, method_name);
			{
				RBinSymbol *sym = R_NEW0 (RBinSymbol);
				strncpy (sym->name, method_name, R_BIN_SIZEOF_STRINGS);
				strcpy (sym->type, "FUNC");
				sym->offset = sym->rva = 0; // UNKNOWN
				r_list_append (bin->imports_list, sym);
			}
			free (method_name);
		}
	}
	free (methods);
	return R_TRUE;
}

static RList* imports (RBinArch *arch) {
	RBinDexObj *bin = (RBinDexObj*) arch->bin_obj;
	if (bin->imports_list)
		return bin->imports_list;
	dex_loadcode (arch, bin);
	return bin->imports_list;
#if 0
	struct r_bin_dex_obj_t *bin = (struct r_bin_dex_obj_t *) arch->bin_obj;
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
		ptr->rva = ptr->offset = getmethodoffset (bin,
			(int)ptr->ordinal, (ut32*)&ptr->size);
dprintf ("____%s__%s____  (%d)  %llx\n", classname,
	methodname, bin->methods[i].name_id, ptr->rva);
free (classname);
free (methodname);
		//strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		if (ptr->rva) {
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
static RList* methods (RBinArch *arch) {
	RBinDexObj *bin = (RBinDexObj*) arch->bin_obj;
	if (bin->methods_list)
		return bin->methods_list;
	dex_loadcode (arch, bin);
	return bin->methods_list;
}

static void __r_bin_class_free(RBinClass *p) {
	r_bin_class_free (p);
}

static RList* classes (RBinArch *arch) {
	struct r_bin_dex_obj_t *bin = (struct r_bin_dex_obj_t *) arch->bin_obj;
	struct dex_class_t entry;
	RList *ret = NULL;
	RBinClass *class;
	int i, len;
	char *name;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = (RListFree)__r_bin_class_free;
	for (i = 0; i < bin->header.class_size; i++) {
		// ETOOSLOW
		r_buf_read_at (bin->b, (ut64) bin->header.class_offset
				+ (sizeof (struct dex_class_t)*i), (ut8*)&entry,
				sizeof (struct dex_class_t));
		// TODO: implement sections.. each section specifies a class boundary
{
		len = 100;
		name = malloc (len);
		if (!name) {
			dprintf ("error malloc string length %d\n", len);
			break;
		}
		if ((entry.source_file>bin->header.strings_size) || (entry.source_file<0))
			continue;
		r_buf_read_at (bin->b, bin->strings[entry.source_file],
				(ut8*)name, len);
		//snprintf (ptr->name, sizeof (ptr->name), "field.%s.%d", name, i);
		class = R_NEW0 (RBinClass);
		class->name = strdup (name[0]<0x41? name+1: name); // TODO: use RConstr here
		class->index = entry.class_id;
		r_list_append (ret, class);

		dprintf ("class.%s=%d\n", name[0]==12?name+1:name, entry.class_id);
		dprintf ("# access_flags = %x;\n", entry.access_flags);
		dprintf ("# super_class = %d;\n", entry.super_class);
		dprintf ("# interfaces_offset = %08x;\n", entry.interfaces_offset);
		//dprintf ("ut32 source_file = %08x;\n", entry.source_file);
		dprintf ("# anotations_offset = %08x;\n", entry.anotations_offset);
		dprintf ("# class_data_offset = %08x;\n", entry.class_data_offset);
		dprintf ("# static_values_offset = %08x;\n\n", entry.static_values_offset);
		free (name);
}
	}
	return ret;
}

static RList* entries(RBinArch *arch) {
	RListIter *iter;
	RBinDexObj *bin = (RBinDexObj*) arch->bin_obj;
	RList *ret = r_list_new ();
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	RBinSymbol *m;
	if (!bin->methods_list)
		dex_loadcode (arch, bin);
	// XXX: entry + main???
	r_list_foreach (bin->methods_list, iter, m) {
		if (strlen (m->name)>=4 && !strcmp (m->name+strlen (m->name)-4, "main")) {
			dprintf ("ENTRY -> %s\n", m->name);
			ptr->offset = ptr->rva = m->offset;
			r_list_append (ret, ptr);
		}
	}
	return ret;
}

//TODO
static int getoffset (RBinArch *arch, int type, int idx) {
	struct r_bin_dex_obj_t *dex = arch->bin_obj;
	switch (type) {
	case 'm': // methods
		if (dex->header.method_size > idx)
			return dex->header.method_offset +
				(sizeof (struct dex_method_t)*idx);
		break;
	case 'c': // class
		break;
	case 'f': // fields
		if (dex->header.fields_size > idx)
			return dex->header.fields_offset +
				(sizeof (struct dex_field_t)*idx);
		break;
	case 'o': // objects
		break;
	case 's': // strings
		if (dex->header.strings_size > idx)
			return dex->strings[idx];
		break;
	case 't': // things
		break;
	}
	return -1;
}

static RList* sections(RBinArch *arch) {
	struct r_bin_dex_obj_t *bin = arch->bin_obj;
	RList *ml = methods (arch);
	RBinSection *ptr = NULL;
	int ns, fsymsz = 0;
	RList *ret = NULL;
	RListIter *iter;
	RBinSymbol *m;
	int fsym = 0;

	r_list_foreach (ml, iter, m) {
		if (fsym == 0 || m->offset<fsym)
			fsym = m->offset;
		ns = m->offset + m->size;
		if (ns > arch->buf->length)
			continue;
		if (ns>fsymsz)
			fsymsz = ns;
	}
	if (fsym == 0)
		return NULL;
	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if ((ptr = R_NEW0 (RBinSection))) {
		strcpy (ptr->name, "code");
		ptr->size = bin->code_to-bin->code_from; //ptr->vsize = fsymsz;
		ptr->offset = bin->code_from; //ptr->rva = fsym;
		ptr->srwx = 4|1;
		r_list_append (ret, ptr);
	}
	if ((ptr = R_NEW0 (RBinSection))) {
		strcpy (ptr->name, "constpool");
		ptr->size = ptr->vsize = fsym;
		ptr->offset = ptr->rva = 0;
		ptr->srwx = 4;
		r_list_append (ret, ptr);
	}
	if ((ptr = R_NEW0 (RBinSection))) {
		strcpy (ptr->name, "data");
		ptr->offset = ptr->rva = fsymsz+fsym;
		if (arch->buf->length > ptr->rva) {
			ptr->size = ptr->vsize = arch->buf->length - ptr->rva;
		} else {
			ptr->size = ptr->vsize = ptr->rva - arch->buf->length;
			// hacky workaround
			dprintf ("Hack\n");
			//ptr->size = ptr->vsize = 1024;
		}
		ptr->srwx = 4; //|2;
		r_list_append (ret, ptr);
	}
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_dex = {
	.name = "dex",
	.desc = "dex format bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = NULL,
	.check = &check,
	.baddr = &baddr,
	.binsym = NULL,
	.entries = entries,
	.classes = classes,
	.sections = sections,
	.symbols = methods,
	.imports = imports,
	.strings = strings,
	.info = &info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.meta = NULL,
	.write = NULL,
	.get_offset = &getoffset
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dex
};
#endif
