#include <r_util.h>

#include "coff.h"

int coff_supported_arch(const ut8 *buf)
{
	ut16 arch = *(ut16*)buf;
	int ret;

	switch (arch) {
	case IMAGE_FILE_MACHINE_AMD64:
	case IMAGE_FILE_MACHINE_I386:
	case IMAGE_FILE_MACHINE_H8300:
	case IMAGE_FILE_TI_COFF:
		ret = R_TRUE;
		break;
	default:
		ret = R_FALSE;
	}

	return ret;
}

static int r_bin_coff_init_hdr(struct r_bin_coff_obj *obj)
{
	size_t offset = 0;

	obj->hdr.machine = *(ut16*)obj->b->buf;

	switch(obj->hdr.machine) {
		case IMAGE_FILE_MACHINE_H8300:
			obj->endian = !LIL_ENDIAN;
			break;
		default:
			obj->endian = LIL_ENDIAN;
	}

	offset += sizeof(ut16);

	r_mem_copyendian((ut8*)&(obj->hdr.sections_num), obj->b->buf + offset,
			sizeof(ut16), obj->endian);

	offset += sizeof(ut16);

	r_mem_copyendian((ut8*)&obj->hdr.timestamp, obj->b->buf + offset,
			sizeof(ut32), obj->endian);
	offset += sizeof(ut32);

	r_mem_copyendian((ut8*)&obj->hdr.symtable_offset, obj->b->buf + offset,
			sizeof(ut32), obj->endian);
	offset += sizeof(ut32);

	r_mem_copyendian((ut8*)&(obj->hdr.symbols_num), obj->b->buf + offset,
			sizeof(ut32), obj->endian);
	offset += sizeof(ut32);

	r_mem_copyendian((ut8*)&(obj->hdr.opt_hdr_size), obj->b->buf + offset,
			sizeof(ut16), obj->endian);
	offset += sizeof(ut16);

	r_mem_copyendian((ut8*)&(obj->hdr.flags), obj->b->buf + offset,
			sizeof(ut16), obj->endian);

       	if (obj->hdr.flags & IMAGE_FLAGS_TI_F_LITTLE) {
		obj->endian = LIL_ENDIAN;
	}
	offset += sizeof(ut16);

	if (obj->hdr.machine == IMAGE_FILE_TI_COFF) {
		r_mem_copyendian((ut8*)&(obj->hdr.target_id), obj->b->buf + offset,
			sizeof(ut16), obj->endian);
	}

	return R_TRUE;
}

static int r_bin_coff_init_opt_hdr(struct r_bin_coff_obj *obj)
{
	size_t offset = 20;

	if (obj->hdr.opt_hdr_size == 0)
		return 0;

	r_mem_copyendian((ut8*)&(obj->opt_hdr.magic), obj->b->buf + offset,
			sizeof(ut16), obj->endian);

	offset += sizeof(ut16);

	r_mem_copyendian((ut8*)&(obj->opt_hdr.major_linker_version),
			obj->b->buf + offset, sizeof(ut8), obj->endian);

	offset += sizeof(ut8);

	r_mem_copyendian((ut8*)&(obj->opt_hdr.minor_linker_version),
			obj->b->buf + offset, sizeof(ut8), obj->endian);

	offset += sizeof(ut8);

	r_mem_copyendian((ut8*)&(obj->opt_hdr.size_of_code),
			obj->b->buf + offset, sizeof(ut32), obj->endian);

	offset += sizeof(ut32);

	r_mem_copyendian((ut8*)&(obj->opt_hdr.size_of_init_data),
			obj->b->buf + offset, sizeof(ut32), obj->endian);

	offset += sizeof(ut32);

	r_mem_copyendian((ut8*)&(obj->opt_hdr.size_of_uninit_data),
			obj->b->buf + offset, sizeof(ut32), obj->endian);

	offset += sizeof(ut32);

	r_mem_copyendian((ut8*)&(obj->opt_hdr.entry_point),
			obj->b->buf + offset, sizeof(ut32), obj->endian);

	offset += sizeof(ut32);

	r_mem_copyendian((ut8*)&(obj->opt_hdr.base_of_code),
			obj->b->buf + offset, sizeof(ut32), obj->endian);

	offset += sizeof(ut32);

	return 0;
}

static int r_bin_coff_init_scn_hdr(struct r_bin_coff_obj *obj)
{
	size_t i, offset = obj->hdr.opt_hdr_size + 20;

	if (obj->hdr.machine == IMAGE_FILE_TI_COFF) {
		offset += 2;
	}

	obj->scn_hdrs = calloc(obj->hdr.sections_num,
			sizeof(struct coff_scn_hdr));

	for (i = 0; i < obj->hdr.sections_num; i++) {
		strncpy(obj->scn_hdrs[i].name, (char*)(obj->b->buf + offset), 8);

		offset += 8;
		r_mem_copyendian((ut8*)&(obj->scn_hdrs[i].virtual_size),
				obj->b->buf + offset, sizeof(ut32), obj->endian);

		offset += sizeof(ut32);

		r_mem_copyendian((ut8*)&(obj->scn_hdrs[i].virtual_addr),
				obj->b->buf + offset, sizeof(ut32), obj->endian);

		offset += sizeof(ut32);

		r_mem_copyendian((ut8*)&(obj->scn_hdrs[i].raw_data_size),
				obj->b->buf + offset, sizeof(ut32), obj->endian);

		offset += sizeof(ut32);

		r_mem_copyendian((ut8*)&(obj->scn_hdrs[i].raw_data_pointer),
				obj->b->buf + offset, sizeof(ut32), obj->endian);

		offset += sizeof(ut32);

		r_mem_copyendian((ut8*)&(obj->scn_hdrs[i].reloc_pointer),
				obj->b->buf + offset, sizeof(ut32), obj->endian);

		offset += sizeof(ut32);

		r_mem_copyendian((ut8*)&(obj->scn_hdrs[i].linenum_pointer),
				obj->b->buf + offset, sizeof(ut32), obj->endian);

		offset += sizeof(ut32);

		r_mem_copyendian((ut8*)&(obj->scn_hdrs[i].reloc_num),
				obj->b->buf + offset, sizeof(ut16), obj->endian);

		offset += sizeof(ut16);

		r_mem_copyendian((ut8*)&(obj->scn_hdrs[i].linenum_num),
				obj->b->buf + offset, sizeof(ut16), obj->endian);

		offset += sizeof(ut16);

		r_mem_copyendian((ut8*)&(obj->scn_hdrs[i].flags),
				obj->b->buf + offset, sizeof(ut32), obj->endian);


		offset += sizeof(ut32);
	}

	return 0;
}

static int r_bin_coff_init_symtable(struct r_bin_coff_obj *obj)
{
	size_t i, offset = obj->hdr.symtable_offset;
	ut32 short_name, ofst;

	obj->symbols = calloc(obj->hdr.symbols_num,
			sizeof(struct coff_symbol));

	for (i = 0; i < obj->hdr.symbols_num; i++) {
		r_mem_copyendian((ut8*)&short_name, obj->b->buf + offset,
				sizeof(ut32), obj->endian);

		if (short_name) {
			obj->symbols[i].name = malloc(sizeof(char) * 9);
			strncpy(obj->symbols[i].name,
					(char*)(obj->b->buf + offset), 8);
			obj->symbols[i].name[8] = '\0';
			offset += 8;
		} else {
			offset += sizeof(ut32);
			r_mem_copyendian((ut8*)&ofst, obj->b->buf + offset,
					sizeof(ut32), obj->endian);

			obj->symbols[i].name = strdup((char*)(obj->b->buf +
					obj->hdr.symtable_offset + ofst +
					obj->hdr.symbols_num * 18));
			offset += sizeof(ut32);
		}

		r_mem_copyendian((ut8*)&(obj->symbols[i].value),
				obj->b->buf + offset,
				sizeof(ut32), obj->endian);

		offset += sizeof(ut32);

		r_mem_copyendian((ut8*)&(obj->symbols[i].scn_num),
				obj->b->buf + offset,
				sizeof(ut16), obj->endian);

		offset += sizeof(ut16);

		r_mem_copyendian((ut8*)&(obj->symbols[i].type),
				obj->b->buf + offset,
				sizeof(ut16), obj->endian);

		offset += sizeof(ut16);

		r_mem_copyendian((ut8*)&(obj->symbols[i].storage_class),
				obj->b->buf + offset,
				sizeof(ut8), obj->endian);

		offset += sizeof(ut8);

		r_mem_copyendian((ut8*)&(obj->symbols[i].aux_sym_num),
				obj->b->buf + offset,
				sizeof(ut8), obj->endian);

		offset += sizeof(ut8);
	}

	return 0;
}

static int r_bin_coff_init(struct r_bin_coff_obj *obj, struct r_buf_t *buf)
{
	obj->size = buf->length;
	obj->b = r_buf_new ();
	obj->size = buf->length;
	if (!r_buf_set_bytes (obj->b, buf->buf, obj->size)){
		r_buf_free (obj->b);
		return R_FALSE;
	}
	r_bin_coff_init_hdr(obj);
	r_bin_coff_init_opt_hdr(obj);

	r_bin_coff_init_scn_hdr(obj);
	r_bin_coff_init_symtable(obj);

	return R_TRUE;
}

void r_bin_coff_free(struct r_bin_coff_obj *obj)
{
	if (obj->scn_hdrs)
		free(obj->scn_hdrs);

	if (obj->symbols)
		free(obj->symbols);

	free(obj);
}

struct r_bin_coff_obj* r_bin_coff_new_buf(struct r_buf_t *buf)
{
	struct r_bin_coff_obj* bin = R_NEW0(struct r_bin_coff_obj);

	r_bin_coff_init(bin, buf);

	return bin;
}
