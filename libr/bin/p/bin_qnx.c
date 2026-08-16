/* radare2 - LGPL3 - 2015-2026 - pancake, deepakchethan */

#include "qnx/qnx.h"
#include "../i/private.h"

static int lmf_header_load(lmf_header *lmfh, RBuffer *buf, Sdb *db) {
	if (r_buf_size (buf) < sizeof (lmf_header)) {
		return false;
	}
	if (r_buf_fread_at (buf, QNX_HEADER_ADDR, (ut8 *)lmfh, "12s6i", 1) != QNX_HDR_SIZE) {
		return false;
	}
	r_strf_buffer (32);
	sdb_set (db, "qnx.version", r_strf ("0x%xH", lmfh->version), 0);
	sdb_set (db, "qnx.cflags", r_strf ("0x%xH", lmfh->cflags), 0);
	sdb_set (db, "qnx.cpu", r_strf ("0x%xH", lmfh->cpu), 0);
	sdb_set (db, "qnx.fpu", r_strf ("0x%xH", lmfh->fpu), 0);
	sdb_set (db, "qnx.code_index", r_strf ("0x%x", lmfh->code_index), 0);
	sdb_set (db, "qnx.stack_index", r_strf ("0x%x", lmfh->stack_index), 0);
	sdb_set (db, "qnx.heap_index", r_strf ("0x%x", lmfh->heap_index), 0);
	sdb_set (db, "qnx.argv_index", r_strf ("0x%x", lmfh->argv_index), 0);
	sdb_set (db, "qnx.code_offset", r_strf ("0x%x", lmfh->code_offset), 0);
	sdb_set (db, "qnx.stack_nbytes", r_strf ("0x%x", lmfh->stack_nbytes), 0);
	sdb_set (db, "qnx.heap_nbytes", r_strf ("0x%x", lmfh->heap_nbytes), 0);
	sdb_set (db, "qnx.image_base", r_strf ("0x%x", lmfh->image_base), 0);
	return true;
}

static bool check(RBinFile *bf, RBuffer *buf) {
	lmf_record record;
	if (r_buf_fread_at (buf, 0, (ut8 *)&record, "ccss", 1) != sizeof (record)) {
		return false;
	}
	ut64 size = r_buf_size (buf);
	return record.rec_type == LMF_HEADER_REC && !record.reserved && !record.spare
		&& record.data_nbytes >= QNX_HDR_SIZE && record.data_nbytes <= size - sizeof (record);
}

// Frees the bin_obj of the binary file
static void destroy(RBinFile *bf) {
	QnxObj *qo = bf->bo->bin_obj;
	RVecRBinSection_fini (&qo->sections);
	RVecRBinReloc_fini (&qo->fixups);
	r_list_free (qo->resources);
	bf->bo->bin_obj = NULL;
	free (qo);
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	QnxObj *qo = R_NEW0 (QnxObj);
	lmf_record lrec;
	lmf_resource lres;
	lmf_data ldata;
	ut64 offset = QNX_RECORD_SIZE;
	RList *resources = NULL;

	if (!qo) {
		goto beach;
	}
	RVecRBinSection_init (&qo->sections);
	RVecRBinReloc_init (&qo->fixups);
	if (!(resources = r_list_newf (free))) {
		goto beach;
	}
	qo->kv = sdb_new0 ();
	if (!qo->kv) {
		goto beach;
	}
	// Read the first record
	if (r_buf_fread_at (bf->buf, 0, (ut8 *)&lrec, "ccss", 1) != QNX_RECORD_SIZE) {
		goto beach;
	}
	// Load the header
	lmf_header_load (&qo->lmfh, bf->buf, qo->kv);
	offset += lrec.data_nbytes;

	for (;;) {
		if (r_buf_fread_at (bf->buf, offset, (ut8 *)&lrec, "ccss", 1) != QNX_RECORD_SIZE) {
			goto beach;
		}
		offset += sizeof (lmf_record);

		if (lrec.rec_type == LMF_IMAGE_END_REC) {
			break;
		} else if (lrec.rec_type == LMF_RESOURCE_REC) {
			if (lrec.data_nbytes < sizeof (lmf_resource)) {
				goto beach;
			}
			if (r_buf_fread_at (bf->buf, offset, (ut8 *)&lres, "ssss", 1) != sizeof (lmf_resource)) {
				goto beach;
			}
			ut64 payload = offset + sizeof (lmf_resource);
			ut64 payload_size = lrec.data_nbytes - sizeof (lmf_resource);
			RBinSection *ptr = RVecRBinSection_emplace_back (&qo->sections);
			ptr->name = strdup ("LMF_RESOURCE");
			ptr->paddr = payload;
			ptr->vsize = payload_size;
			ptr->size = ptr->vsize;
			ptr->add = true;
			QnxResourceEntry *resource = R_NEW0 (QnxResourceEntry);
			resource->type = lres.res_type;
			resource->paddr = payload;
			resource->size = payload_size;
			r_list_append (resources, resource);
		} else if (lrec.rec_type == LMF_LOAD_REC) {
			if (r_buf_fread_at (bf->buf, offset, (ut8 *)&ldata, "si", 1) != sizeof (lmf_data)) {
				goto beach;
			}
			if (lrec.data_nbytes < sizeof (lmf_data)) {
				goto beach;
			}
			RBinSection *ptr = RVecRBinSection_emplace_back (&qo->sections);
			ptr->name = strdup ("LMF_LOAD");
			ptr->paddr = offset;
			ptr->vaddr = ldata.offset;
			ptr->vsize = lrec.data_nbytes - sizeof (lmf_data);
			ptr->size = ptr->vsize;
			ptr->add = true;
		} else if (lrec.rec_type == LMF_FIXUP_REC || lrec.rec_type == LMF_8087_FIXUP_REC) {
			if (r_buf_fread_at (bf->buf, offset, (ut8 *)&ldata, "si", 1) != sizeof (lmf_data)) {
				goto beach;
			}
			RBinReloc *ptr = RVecRBinReloc_emplace_back (&qo->fixups);
			ptr->vaddr = ptr->paddr = ldata.offset;
			ptr->type = (lrec.rec_type == LMF_FIXUP_REC)? 'f': 'F'; // "LMF_FIXUP" / "LMF_8087_FIXUP"
		} else if (lrec.rec_type == LMF_RW_END_REC) {
			r_buf_fread_at (bf->buf, offset, (ut8 *)&qo->rwend, "si", 1);
		}
		offset += lrec.data_nbytes;
	}
	sdb_ns_set (bf->sdb, "info", qo->kv);
	qo->resources = resources;
	bf->bo->bin_obj = qo;
	return true;
beach:
	if (qo) {
		sdb_free (qo->kv);
		RVecRBinSection_fini (&qo->sections);
		RVecRBinReloc_fini (&qo->fixups);
		free (qo);
	}
	r_list_free (resources);
	return false;
}

/*
 * Provides the info about the binary file
 * @param RBinFile to extract the data from
 * @return RBinInfo file with the info
 */
static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = strdup ("QNX Executable");
	ret->bclass = strdup ("qnx");
	ret->machine = strdup ("i386");
	ret->rclass = strdup ("QNX");
	ret->arch = strdup ("x86");
	ret->os = strdup ("any");
	ret->subsystem = strdup ("any");
	ret->lang = "C/C++";
	ret->signature = true;
	return ret;
}

static RVecRBinReloc *relocs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	QnxObj *qo = bf->bo->bin_obj;
	if (!qo) {
		return NULL;
	}
	RVecRBinReloc *ret = RVecRBinReloc_new ();
	if (ret) {
		RVecRBinReloc_swap (ret, &qo->fixups);
	}
	return ret;
}

static char *header(RBinFile *bf, int mode) {
	if (!bf || !bf->bo || !bf->rbin) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
#define p(f,...) r_strbuf_appendf (sb, f, ##__VA_ARGS__)
	QnxObj *bin = bf->bo->bin_obj;
	p ("QNX file header:\n");
	p ("version : 0x%xH\n", bin->lmfh.version);
	p ("cflags : 0x%xH\n", bin->lmfh.cflags);
	p ("cpu : 0x%xH\n", bin->lmfh.cpu);
	p ("fpu : 0x%xH\n", bin->lmfh.fpu);
	p ("code_index : 0x%xH\n", bin->lmfh.code_index);
	p ("stack_index : 0x%xH\n", bin->lmfh.stack_index);
	p ("heap_index : 0x%xH\n", bin->lmfh.heap_index);
	p ("argv_index : 0x%xH\n", bin->lmfh.argv_index);
	p ("spare2[4] : 0x0H\n");
	p ("code_offset : 0x%xH\n", bin->lmfh.code_offset);
	p ("stack_nbytes : 0x%xH\n", bin->lmfh.stack_nbytes);
	p ("heap_nbytes : 0x%xH\n", bin->lmfh.heap_nbytes);
	p ("image_base : 0x%xH\n", bin->lmfh.image_base);
	p ("spare3[2] : 0x0H\n");
#undef p
	return r_strbuf_drain (sb);
}

/*
 * No mention of symbols in the doc
 */
static bool symbols_vec(RBinFile *bf) {
	return true;
}

static bool sections_vec(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, false);
	QnxObj *qo = bf->bo->bin_obj;
	if (!qo) {
		return false;
	}
	RVecRBinSection_swap (&bf->bo->sections_vec, &qo->sections);
	return true;
}

static const char *resource_type_name(ut16 type) {
	return type == RES_USAGE? "USAGE": "RESOURCE";
}

static bool load_resources(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, false);
	QnxObj *qo = bf->bo->bin_obj;
	if (!qo || !qo->resources) {
		return false;
	}
	ut32 index = 0;
	RListIter *iter;
	QnxResourceEntry *entry;
	r_list_foreach (qo->resources, iter, entry) {
		RBinResource *resource = RVecRBinResource_emplace_back (&bf->bo->resources_vec);
		if (!resource) {
			return false;
		}
		resource->type = strdup (resource_type_name (entry->type));
		if (!resource->type) {
			return false;
		}
		resource->paddr = entry->paddr;
		resource->vaddr = entry->paddr;
		resource->size = entry->size;
		resource->id = UT64_MAX;
		resource->index = index++;
		resource->type_id = entry->type;
	}
	return true;
}

/*
 * Returns the sdb
 * @param RBinFile
 * @return sdb of the bin_obj
 */
static Sdb *get_sdb(RBinFile *bf) {
	RBinObject *o = bf->bo;
	if (!o) {
		return NULL;
	}
	QnxObj *qo = o->bin_obj;
	return qo? qo->kv: NULL;
}

/*
 * Returns the base address of the image from the binary header
 * @param RBinFile
 * @return image_base address
 */
static ut64 baddr(RBinFile *bf) {
	QnxObj *qo = bf->bo->bin_obj;
	return qo? qo->lmfh.image_base: 0;
}

/*
 * Currently both physical and virtual address are set to 0
 * The memory map has different values for entry
 */
static RList* entries(RBinFile *bf) {
	RList *ret;
	QnxObj *qo = bf->bo->bin_obj;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	ptr->paddr = qo->lmfh.code_offset;
	ptr->vaddr = qo->lmfh.code_offset + baddr (bf);
	r_list_append (ret, ptr);
	return ret;
}

static char *signature(RBinFile *bf, bool json) {
 	char buf[SDB_NUM_BUFSZ];
 	QnxObj *qo = bf->bo->bin_obj;
	return qo? strdup (sdb_itoa (qo->rwend.signature, 10, buf, sizeof (buf))): NULL;
}

static ut64 get_vaddr(RBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	return vaddr;
}

// Declaration of the plugin
RBinPlugin r_bin_plugin_qnx = {
	.meta = {
		.name = "qnx",
		.author = "deepakchethan",
		.desc = "Quantum Software Systems (QNX) executable",
		.license = "LGPL-3.0-only",
	},
	.weak_guess = true,
	.load = &load,
	.destroy = &destroy,
	.relocs = &relocs,
	.baddr = &baddr,
	.check = &check,
	.header = &header,
	.get_sdb = &get_sdb,
	.entries = &entries,
	.sections_vec = &sections_vec,
	.symbols_vec = &symbols_vec,
	.signature = &signature,
	.get_vaddr = &get_vaddr,
	.info = &info,
	.load_resources = &load_resources
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_qnx,
	.version = R2_VERSION
};
#endif
