#include <r_util.h>

#include "coff.h"

int coff_supported_arch(const ut8 *buf)
{
	ut16 arch = *(ut16*)buf;
	int ret;

	switch (arch) {
	case 0x8300:
		ret = R_TRUE;
		break;
	default:
		ret = R_FALSE;
	}

	return R_TRUE;
}

static int r_bin_coff_init_hdr(struct r_bin_coff_obj *obj)
{
	size_t offset = 0;

	obj->endian = !LIL_ENDIAN;

	r_mem_copyendian((ut8*)&(obj->hdr.machine), obj->b->buf,
			sizeof(ut16), obj->endian);
	offset += sizeof(ut16);

	printf("machine 0x%x\n", obj->hdr.machine);

	r_mem_copyendian((ut8*)&(obj->hdr.sections_num), obj->b->buf + offset,
			sizeof(ut16), obj->endian);

	offset += sizeof(ut16);

	printf("sections num %x\n", obj->hdr.sections_num);

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
	printf("opt hdr size %u\n", obj->hdr.opt_hdr_size);

	r_mem_copyendian((ut8*)&(obj->hdr.flags), obj->b->buf + offset,
			sizeof(ut16), obj->endian);

	return R_TRUE;
}

static int r_bin_coff_init_opt_hdr(struct r_bin_coff_obj *obj)
{
	return R_TRUE;
}

static int r_bin_coff_init_scn_hdr(struct r_bin_coff_obj *obj)
{
	size_t i, offset = obj->hdr.opt_hdr_size + 20;

	obj->scn_hdrs = calloc(obj->hdr.sections_num,
			sizeof(struct coff_scn_hdr));

	for (i = 0; i < obj->hdr.sections_num; i++) {
		strncpy(obj->scn_hdrs[i].name, (char*)(obj->b->buf + offset), 8);
		printf("section name %s\n", obj->scn_hdrs[i].name);

		offset += 8;
		r_mem_copyendian((ut8*)&(obj->scn_hdrs[i].virtual_size),
				obj->b->buf + offset, sizeof(ut32), obj->endian);

		offset += sizeof(ut32);

		r_mem_copyendian((ut8*)&(obj->scn_hdrs[i].virtual_addr),
				obj->b->buf + offset, sizeof(ut32), obj->endian);

		printf("virtial addr %x\n", obj->scn_hdrs[i].virtual_addr);

		offset += sizeof(ut32);

		r_mem_copyendian((ut8*)&(obj->scn_hdrs[i].raw_data_size),
				obj->b->buf + offset, sizeof(ut32), obj->endian);

		offset += sizeof(ut32);

		r_mem_copyendian((ut8*)&(obj->scn_hdrs[i].raw_data_pointer),
				obj->b->buf + offset, sizeof(ut32), obj->endian);

		printf("raw_data_pointer %x\n", obj->scn_hdrs[i].raw_data_pointer);

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

		offset += 10;
//		printf ("symbol %s\n", obj->symbols[i].name);
	}
}

static int r_bin_coff_init(struct r_bin_coff_obj *obj, struct r_buf_t *buf)
{
	obj->b = buf;
	obj->size = buf->length;

	r_bin_coff_init_hdr(obj);
	r_bin_coff_init_opt_hdr(obj);

	r_bin_coff_init_scn_hdr(obj);
	r_bin_coff_init_symtable(obj);

	return R_TRUE;
}

void r_bin_coff_free(struct r_bin_coff_obj *obj)
{
}

struct r_bin_coff_obj* r_bin_coff_new_buf(struct r_buf_t *buf)
{
	struct r_bin_coff_obj* bin = R_NEW0(struct r_bin_coff_obj);

	r_bin_coff_init(bin, buf);

	return bin;
}
