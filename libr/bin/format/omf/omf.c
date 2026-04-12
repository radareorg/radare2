#include "omf.h"

static bool is_valid_omf_type(ut8 type) {
	const ut8 types[] = {
		OMF_THEADR, OMF_LHEADR, OMF_COMENT, OMF_MODEND, OMF_MODEND32,
		OMF_EXTDEF, OMF_PUBDEF, OMF_PUBDEF32, OMF_LINNUM,
		OMF_LINNUM32, OMF_LNAMES, OMF_LNAMES, OMF_SEGDEF,
		OMF_SEGDEF32, OMF_GRPDEF, OMF_FIXUPP, OMF_FIXUPP32,
		OMF_LEDATA, OMF_LEDATA32, OMF_LIDATA, OMF_LIDATA32,
		OMF_COMDEF, OMF_BAKPAT, OMF_BAKPAT32, OMF_LEXTDEF,
		OMF_LPUBDEF, OMF_LPUBDEF32, OMF_LCOMDEF, OMF_CEXTDEF,
		OMF_COMDAT, OMF_COMDAT32, OMF_LINSYM, OMF_LINSYM32,
		OMF_ALIAS, OMF_NBKPAT, OMF_NBKPAT32, OMF_LLNAMES, OMF_VERNUM,
		OMF_VENDEXT, 0
	};
	int i;
	for (i = 0; types[i]; i++) {
		if (type == types[i]) {
			return true;
		}
	}
	return false;
}

bool r_bin_checksum_omf_ok(const ut8 *buf, ut64 buf_size) {
	if (buf_size < 3) {
		R_LOG_ERROR ("Invalid record (too short)");
		return false;
	}
	ut16 size = r_read_le16 (buf + 1);
	if (buf_size < (ut32)size + 3) {
		R_LOG_ERROR ("Invalid record (too short)");
		return false;
	}
	// some compilers set checksum to 0
	if (!buf[size + 2]) {
		return true;
	}
	ut8 checksum = 0;
	ut32 total = (ut32)size + 3;
	ut32 i;
	for (i = 0; i < total; i++) {
		checksum += buf[i];
	}
	return !checksum;
}

static ut16 omf_get_idx(const ut8 *buf, int buf_size) {
	if (buf_size < 2) {
		return 0;
	}
	if (*buf & 0x80) {
		return (ut16)((*buf & 0x7f) * 0x100 + buf[1]);
	}
	return *buf;
}

static void free_lname(OMF_multi_datas *lname) {
	if (lname->elems) {
		ut32 i;
		for (i = 0; i < lname->nb_elem; i++) {
			R_FREE (((char **)lname->elems)[i]);
		}
		R_FREE (lname->elems);
	}
	R_FREE (lname);
}

static void free_pubdef(OMF_multi_datas *datas) {
	if (datas->elems) {
		ut32 i;
		for (i = 0; i < datas->nb_elem; i++) {
			R_FREE (((OMF_symbol *)datas->elems)[i].name);
		}
		R_FREE (datas->elems);
	}
	R_FREE (datas);
}

static bool load_omf_lnames(OMF_record *record, const ut8 *buf, ut64 buf_size) {
	ut32 tmp_size = 0;
	ut32 ct_name = 0;
	OMF_multi_datas *ret = R_NEW0 (OMF_multi_datas);
	record->content = ret;

	while ((int)tmp_size < (int)(record->size - 1)) {
		ut64 idx = 3 + tmp_size;
		if (idx >= buf_size) {
			break;
		}
		int next = buf[idx] + 1;
		ret->nb_elem++;
		if (next < 1) {
			break;
		}
		tmp_size += next;
	}
	if (!(ret->elems = R_NEWS0 (char *, ret->nb_elem + 1))) {
		free_lname (ret);
		record->content = NULL;
		return false;
	}
	char **names = (char **)ret->elems;
	tmp_size = 0;
	while ((int)tmp_size < (int)(record->size - 1)) {
		if (ct_name >= ret->nb_elem) {
			R_LOG_WARN ("load_omf_lnames: prevent overflow");
			break;
		}
		ut64 idx = 3 + tmp_size;
		if (idx >= buf_size) {
			break;
		}
		// sometimes there is a name with a null size so we just skip it
		char cb = buf[idx];
		if (cb < 1) {
			names[ct_name++] = NULL;
			tmp_size++;
			continue;
		}
		if (record->size + 3 < tmp_size + cb) {
			R_LOG_ERROR ("Invalid Lnames record (bad size)");
			free_lname (ret);
			record->content = NULL;
			return false;
		}
		if (!(names[ct_name] = R_NEWS0 (char, cb + 1))) {
			free_lname (ret);
			record->content = NULL;
			return false;
		}
		if ((tmp_size + 4 + cb) < buf_size) {
			memcpy (names[ct_name], buf + 3 + tmp_size + 1, cb);
		}
		ct_name++;
		tmp_size += cb + 1;
	}
	return true;
}

static bool load_omf_segdef(OMF_record *record, const ut8 *buf, ut64 buf_size) {
	if (record->size < 2 || buf_size < 4) {
		R_LOG_ERROR ("Invalid Segdef record (bad size)");
		return false;
	}
	int off_add = (buf[3] & 0xe) ? 0 : 3;
	OMF_segment *ret = R_NEW0 (OMF_segment);

	if (record->type == OMF_SEGDEF32) {
		if (record->size < 5 + off_add || buf_size < (ut64)(9 + off_add)) {
			R_LOG_ERROR ("Invalid Segdef record (bad size)");
			free (ret);
			return false;
		}
		ret->name_idx = omf_get_idx (buf + 8 + off_add, buf_size - 8 - off_add);
		if (buf[3] & 2) {
			ret->size = UT32_MAX;
		} else {
			ret->size = r_read_le32 (buf + 4 + off_add);
		}
	} else {
		if (record->size < 3 + off_add || buf_size < (ut64)(7 + off_add)) {
			R_LOG_ERROR ("Invalid Segdef record (bad size)");
			free (ret);
			return false;
		}
		ret->name_idx = omf_get_idx (buf + 6 + off_add, buf_size - 6 - off_add);
		if (buf[3] & 2) {
			ret->size = UT16_MAX;
		} else {
			ret->size = r_read_le16 (buf + 4 + off_add);
		}
	}

	ret->bits = (buf[3] & 1) ? 32 : 16;
	record->content = ret;
	// normalize type for consistent indexing
	record->type = OMF_SEGDEF;
	return true;
}

static ut32 omf_count_symb(ut16 total_size, ut32 ct, const ut8 *buf, int buf_size, int bits) {
	ut32 nb_symb = 0;
	ut32 limit = R_MIN (total_size, (ut32)buf_size);
	if (limit < 2) {
		return 0;
	}
	while (ct < limit - 1) {
		ct += buf[ct] + 1 + (bits == 32 ? 4 : 2);
		if (ct > limit - 1) {
			return nb_symb;
		}
		if (buf[ct] & 0x80) {
			ct += 2;
		} else {
			ct++;
		}
		nb_symb++;
	}
	return nb_symb;
}

static bool load_omf_symb(OMF_record *record, ut32 ct, const ut8 *buf, int buf_size, int bits, ut16 seg_idx) {
	OMF_multi_datas *multi = (OMF_multi_datas *)record->content;
	OMF_symbol *symbols = (OMF_symbol *)multi->elems;
	int off = (bits == 32) ? 4 : 2;
	ut32 nb_symb = 0;

	while (nb_symb < multi->nb_elem) {
		OMF_symbol *sym = &symbols[nb_symb];
		if (record->size - 1 < ct - 2) {
			R_LOG_ERROR ("Invalid Pubdef record (bad size)");
			return false;
		}
		ut8 str_size = buf[ct];
		if (ct + 1 + str_size + off - 3 > record->size) {
			R_LOG_ERROR ("Invalid Pubdef record (bad size)");
			return false;
		}
		if (bits == 32) {
			sym->offset = r_read_le32 (buf + ct + 1 + str_size);
		} else {
			sym->offset = r_read_le16 (buf + ct + 1 + str_size);
		}
		sym->seg_idx = seg_idx;
		if (!(sym->name = R_NEWS0 (char, str_size + 1))) {
			return false;
		}
		memcpy (sym->name, buf + ct + 1, str_size);
		ct += 1 + str_size + off;
		if (ct >= (ut32)buf_size) {
			return false;
		}
		if (buf[ct] & 0x80) {
			ct += 2;
		} else {
			ct++;
		}
		nb_symb++;
	}
	return true;
}

static bool load_omf_pubdef(OMF_record *record, const ut8 *buf, int buf_size) {
	ut16 ct = 3;
	if (record->size < 2) {
		R_LOG_ERROR ("Invalid Pubdef record (bad size)");
		return false;
	}
	ut16 base_grp = omf_get_idx (buf + ct, buf_size - ct);
	ct += (buf[ct] & 0x80) ? 2 : 1;
	if (record->size < ct - 2) {
		R_LOG_ERROR ("Invalid Pubdef record (bad size)");
		return false;
	}
	ut16 seg_idx = omf_get_idx (buf + ct, buf_size - ct);
	ct += (buf[ct] & 0x80) ? 2 : 1;
	if (!base_grp && !seg_idx) {
		ct += 2;
	}
	if (record->size < ct - 2) {
		R_LOG_ERROR ("Invalid Pubdef record (bad size)");
		return false;
	}

	OMF_multi_datas *ret = R_NEW0 (OMF_multi_datas);
	record->content = ret;
	int bits = (record->type & 1) ? 32 : 16;
	ret->nb_elem = omf_count_symb (record->size + 3, ct, buf, buf_size, bits);
	if (ret->nb_elem > 0) {
		if (!(ret->elems = R_NEWS0 (OMF_symbol, ret->nb_elem))) {
			free_pubdef (ret);
			record->content = NULL;
			return false;
		}
	}
	if (!load_omf_symb (record, ct, buf, buf_size, bits, seg_idx)) {
		free_pubdef (ret);
		record->content = NULL;
		return false;
	}
	// normalize type for consistent indexing
	record->type = OMF_PUBDEF;
	return true;
}

static bool load_omf_data(const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	ut16 ct = 4;
	if ((!(record->type & 1) && record->size < 4) || (record->size < 6)) {
		R_LOG_ERROR ("Invalid Ledata record (bad size)");
		return false;
	}
	ut16 seg_idx = omf_get_idx (buf + 3, buf_size - 3);
	if (seg_idx & 0xff00) {
		if ((!(record->type & 1) && record->size < 5) || (record->size < 7)) {
			R_LOG_ERROR ("Invalid Ledata record (bad size)");
			return false;
		}
		ct++;
	}
	ut32 offset;
	if (record->type == OMF_LEDATA32) {
		offset = r_read_le32 (buf + ct);
		ct += 4;
	} else {
		offset = r_read_le16 (buf + ct);
		ct += 2;
	}
	OMF_data *ret = R_NEW0 (OMF_data);
	record->content = ret;
	ret->size = record->size - 1 - (ct - 3);
	ret->paddr = global_ct + ct;
	ret->offset = offset;
	ret->seg_idx = seg_idx;
	record->type = OMF_LEDATA;
	return true;
}

static bool load_omf_content(OMF_record *record, const ut8 *buf, ut64 global_ct, ut64 buf_size) {
	if (record->type == OMF_LNAMES) {
		return load_omf_lnames (record, buf, buf_size);
	}
	if (record->type == OMF_SEGDEF || record->type == OMF_SEGDEF32) {
		return load_omf_segdef (record, buf, buf_size);
	}
	if (record->type == OMF_PUBDEF || record->type == OMF_PUBDEF32
			|| record->type == OMF_LPUBDEF || record->type == OMF_LPUBDEF32) {
		return load_omf_pubdef (record, buf, buf_size);
	}
	if (record->type == OMF_LEDATA || record->type == OMF_LEDATA32) {
		return load_omf_data (buf, buf_size, record, global_ct);
	}
	// generic loader
	if (!record->size) {
		R_LOG_ERROR ("Invalid record (size too short)");
		return false;
	}
	if (!(record->content = R_NEWS0 (char, record->size))) {
		return false;
	}
	((char *)record->content)[record->size - 1] = 0;
	return true;
}

static OMF_record_handler *load_record_omf(const ut8 *buf, ut64 global_ct, ut64 buf_size) {
	if (!is_valid_omf_type (*buf) || !r_bin_checksum_omf_ok (buf, buf_size)) {
		return NULL;
	}
	OMF_record_handler *new = R_NEW0 (OMF_record_handler);
	OMF_record *rec = (OMF_record *)new;
	rec->type = *buf;
	rec->size = r_read_le16 (buf + 1);
	if (rec->size > buf_size - 3 || buf_size < 4) {
		R_LOG_ERROR ("Invalid record (too short)");
		R_FREE (new);
		return NULL;
	}
	if (!load_omf_content (rec, buf, global_ct, buf_size)) {
		R_FREE (new);
		return NULL;
	}
	rec->checksum = buf[2 + rec->size];
	return new;
}

static bool load_all_omf_records(r_bin_omf_obj *obj, const ut8 *buf, ut64 size) {
	ut64 ct = 0;
	OMF_record_handler *tmp = NULL;

	while (ct < size) {
		OMF_record_handler *new_rec = load_record_omf (buf + ct, ct, size - ct);
		if (!new_rec) {
			return false;
		}
		if (tmp) {
			tmp->next = new_rec;
		} else {
			obj->records = new_rec;
		}
		tmp = new_rec;
		ct += 3 + ((OMF_record *)tmp)->size;
	}
	return true;
}

static ut32 count_omf_record_type(r_bin_omf_obj *obj, ut8 type) {
	OMF_record_handler *tmp = obj->records;
	ut32 ct = 0;
	while (tmp) {
		if (((OMF_record *)tmp)->type == type) {
			ct++;
		}
		tmp = tmp->next;
	}
	return ct;
}

static ut32 count_omf_multi_record_type(r_bin_omf_obj *obj, ut8 type) {
	OMF_record_handler *tmp = obj->records;
	ut32 ct = 0;
	while (tmp) {
		OMF_record *rec = (OMF_record *)tmp;
		if (rec->type == type) {
			ct += ((OMF_multi_datas *)rec->content)->nb_elem;
		}
		tmp = tmp->next;
	}
	return ct;
}

static OMF_record_handler *get_next_omf_record_type(OMF_record_handler *tmp, ut8 type) {
	while (tmp) {
		if (((OMF_record *)tmp)->type == type) {
			return tmp;
		}
		tmp = tmp->next;
	}
	return NULL;
}

static bool cpy_omf_names(r_bin_omf_obj *obj) {
	OMF_record_handler *tmp = obj->records;
	int ct_obj = 0;

	while ((tmp = get_next_omf_record_type (tmp, OMF_LNAMES))) {
		OMF_multi_datas *lname = (OMF_multi_datas *)((OMF_record *)tmp)->content;
		char **elems = (char **)lname->elems;
		int ct_rec;
		for (ct_rec = 0; ct_rec < (int)lname->nb_elem; ct_rec++) {
			if (elems[ct_rec] && !(obj->names[ct_obj] = strdup (elems[ct_rec]))) {
				return false;
			}
			ct_obj++;
		}
		tmp = tmp->next;
	}
	return true;
}

static void get_omf_section_info(r_bin_omf_obj *obj) {
	OMF_record_handler *tmp = obj->records;
	ut32 ct_obj = 0;

	while ((tmp = get_next_omf_record_type (tmp, OMF_SEGDEF))) {
		OMF_record *rec = (OMF_record *)tmp;
		obj->sections[ct_obj] = rec->content;
		rec->content = NULL;
		if (ct_obj > 0) {
			OMF_segment *prev = obj->sections[ct_obj - 1];
			obj->sections[ct_obj]->vaddr = prev->vaddr + prev->size;
		} else {
			obj->sections[ct_obj]->vaddr = 0;
		}
		ct_obj++;
		tmp = tmp->next;
	}
}

static bool get_omf_symbol_info(r_bin_omf_obj *obj) {
	OMF_record_handler *tmp = obj->records;
	int ct_obj = 0;

	while ((tmp = get_next_omf_record_type (tmp, OMF_PUBDEF))) {
		OMF_multi_datas *symbols = (OMF_multi_datas *)((OMF_record *)tmp)->content;
		OMF_symbol *elems = (OMF_symbol *)symbols->elems;
		int ct_rec;
		for (ct_rec = 0; ct_rec < (int)symbols->nb_elem; ct_rec++) {
			OMF_symbol *sym = R_NEW0 (OMF_symbol);
			memcpy (sym, &elems[ct_rec], sizeof (OMF_symbol));
			sym->name = strdup (elems[ct_rec].name);
			obj->symbols[ct_obj++] = sym;
		}
		tmp = tmp->next;
	}
	return true;
}

static bool get_omf_data_info(r_bin_omf_obj *obj) {
	OMF_record_handler *tmp = obj->records;

	while ((tmp = get_next_omf_record_type (tmp, OMF_LEDATA))) {
		OMF_data *data = (OMF_data *)((OMF_record *)tmp)->content;
		if (data->seg_idx < 1 || data->seg_idx - 1 >= obj->nb_section) {
			R_LOG_ERROR ("Invalid Ledata record (bad segment index)");
			return false;
		}
		OMF_segment *seg = obj->sections[data->seg_idx - 1];
		if (seg->data) {
			OMF_data *tail = seg->data;
			while (tail->next) {
				tail = tail->next;
			}
			tail->next = data;
		} else {
			seg->data = data;
		}
		((OMF_record *)tmp)->content = NULL;
		tmp = tmp->next;
	}
	return true;
}

static bool get_omf_infos(r_bin_omf_obj *obj) {
	obj->nb_name = count_omf_multi_record_type (obj, OMF_LNAMES);
	if (obj->nb_name > 0) {
		if (!(obj->names = R_NEWS0 (char *, obj->nb_name))) {
			return false;
		}
		if (!cpy_omf_names (obj)) {
			return false;
		}
	}
	obj->nb_section = count_omf_record_type (obj, OMF_SEGDEF);
	if (obj->nb_section > 0) {
		if (!(obj->sections = R_NEWS0 (OMF_segment *, obj->nb_section))) {
			return false;
		}
		get_omf_section_info (obj);
	}
	get_omf_data_info (obj);
	obj->nb_symbol = count_omf_multi_record_type (obj, OMF_PUBDEF);
	if (obj->nb_symbol > 0) {
		if (!(obj->symbols = R_NEWS0 (OMF_symbol *, obj->nb_symbol))) {
			return false;
		}
		if (!get_omf_symbol_info (obj)) {
			return false;
		}
	}
	return true;
}

static void free_all_omf_records(r_bin_omf_obj *obj) {
	OMF_record_handler *rec = obj->records;
	while (rec) {
		OMF_record *r = (OMF_record *)rec;
		OMF_record_handler *next = rec->next;
		if (r->type == OMF_LNAMES) {
			if (r->content) {
				free_lname ((OMF_multi_datas *)r->content);
			}
		} else if (r->type == OMF_PUBDEF) {
			if (r->content) {
				free_pubdef ((OMF_multi_datas *)r->content);
			}
		} else {
			R_FREE (r->content);
		}
		R_FREE (rec);
		rec = next;
	}
	obj->records = NULL;
}

static void free_all_omf_sections(r_bin_omf_obj *obj) {
	ut32 ct;
	for (ct = 0; ct < obj->nb_section; ct++) {
		if (!obj->sections[ct]) {
			continue;
		}
		while (obj->sections[ct]->data) {
			OMF_data *next = obj->sections[ct]->data->next;
			R_FREE (obj->sections[ct]->data);
			obj->sections[ct]->data = next;
		}
		R_FREE (obj->sections[ct]);
	}
	R_FREE (obj->sections);
}

static void free_all_omf_symbols(r_bin_omf_obj *obj) {
	ut32 ct;
	for (ct = 0; ct < obj->nb_symbol; ct++) {
		if (!obj->symbols[ct]) {
			continue;
		}
		R_FREE (obj->symbols[ct]->name);
		R_FREE (obj->symbols[ct]);
	}
	R_FREE (obj->symbols);
}

static void free_all_omf_names(r_bin_omf_obj *obj) {
	ut32 ct;
	for (ct = 0; ct < obj->nb_name; ct++) {
		R_FREE (obj->names[ct]);
	}
	R_FREE (obj->names);
}

void r_bin_free_all_omf_obj(r_bin_omf_obj *obj) {
	if (obj) {
		if (obj->records) {
			free_all_omf_records (obj);
		}
		if (obj->sections) {
			free_all_omf_sections (obj);
		}
		if (obj->symbols) {
			free_all_omf_symbols (obj);
		}
		if (obj->names) {
			free_all_omf_names (obj);
		}
		free (obj);
	}
}

r_bin_omf_obj *r_bin_internal_omf_load(const ut8 *buf, ut64 size) {
	r_bin_omf_obj *ret = R_NEW0 (r_bin_omf_obj);
	if (!load_all_omf_records (ret, buf, size)) {
		r_bin_free_all_omf_obj (ret);
		return NULL;
	}
	if (!get_omf_infos (ret)) {
		r_bin_free_all_omf_obj (ret);
		return NULL;
	}
	free_all_omf_records (ret);
	return ret;
}

bool r_bin_omf_get_entry(r_bin_omf_obj *obj, RBinAddr *addr) {
	if (!obj) {
		return false;
	}
	ut32 ct_sym;
	for (ct_sym = 0; ct_sym < obj->nb_symbol; ct_sym++) {
		OMF_symbol *sym = obj->symbols[ct_sym];
		if (strcmp (sym->name, "_start")) {
			continue;
		}
		if (sym->seg_idx < 1 || sym->seg_idx - 1 >= obj->nb_section) {
			R_LOG_ERROR ("Invalid segment index for symbol _start");
			return false;
		}
		OMF_segment *seg = obj->sections[sym->seg_idx - 1];
		addr->vaddr = seg->vaddr + sym->offset + OMF_BASE_ADDR;
		ut32 offset = 0;
		OMF_data *data = seg->data;
		while (data) {
			offset += data->size;
			if (sym->offset < offset) {
				addr->paddr = (sym->offset - data->offset) + data->paddr;
				return true;
			}
			data = data->next;
		}
	}
	return false;
}

int r_bin_omf_get_bits(r_bin_omf_obj *obj) {
	if (!obj) {
		return 32;
	}
	ut32 ct_sec;
	for (ct_sec = 0; ct_sec < obj->nb_section; ct_sec++) {
		if (obj->sections[ct_sec]->bits == 32) {
			return 32;
		}
	}
	return 16;
}

int r_bin_omf_send_sections(RList *list, OMF_segment *section, r_bin_omf_obj *obj) {
	OMF_data *data = section->data;
	ut32 ct_name = 1;

	while (data) {
		RBinSection *new = R_NEW0 (RBinSection);
		if (section->name_idx && section->name_idx - 1 < obj->nb_name) {
			new->name = r_str_newf ("%s_%d", obj->names[section->name_idx - 1], ct_name++);
		} else {
			new->name = r_str_newf ("no_name_%d", ct_name++);
		}
		new->size = data->size;
		new->vsize = data->size;
		new->paddr = data->paddr;
		new->vaddr = section->vaddr + data->offset + OMF_BASE_ADDR;
		new->perm = R_PERM_RWX;
		new->add = true;
		r_list_append (list, new);
		data = data->next;
	}
	return true;
}

ut64 r_bin_omf_get_paddr_sym(r_bin_omf_obj *obj, OMF_symbol *sym) {
	if (!obj->sections || sym->seg_idx < 1 || sym->seg_idx - 1 >= obj->nb_section) {
		return 0;
	}
	OMF_data *data = obj->sections[sym->seg_idx - 1]->data;
	ut64 offset = 0;
	while (data) {
		offset += data->size;
		if (sym->offset < offset) {
			return sym->offset - data->offset + data->paddr;
		}
		data = data->next;
	}
	return 0;
}

ut64 r_bin_omf_get_vaddr_sym(r_bin_omf_obj *obj, OMF_symbol *sym) {
	if (!obj->sections || sym->seg_idx < 1) {
		return 0;
	}
	if (sym->seg_idx - 1 >= obj->nb_section) {
		R_LOG_ERROR ("Invalid segment index for symbol %s", sym->name);
		return 0;
	}
	return obj->sections[sym->seg_idx - 1]->vaddr + sym->offset + OMF_BASE_ADDR;
}
