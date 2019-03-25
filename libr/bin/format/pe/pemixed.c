/* radare - LGPL - Copyright 2018 - JohnPeng47 */

#include <stdio.h>
#include "pemixed.h"

static bool check_il_only(ut32 flags);

static int r_bin_pemixed_init(struct r_bin_pemixed_obj_t* bin, struct PE_(r_bin_pe_obj_t)* pe_bin) {
	struct PE_(r_bin_pe_obj_t)* sub_bin_dos;
	struct PE_(r_bin_pe_obj_t)* sub_bin_native;
	struct PE_(r_bin_pe_obj_t)* sub_bin_net;

	sub_bin_dos = r_bin_pemixed_init_dos (pe_bin);
	if (sub_bin_dos) {
		bin->sub_bin_dos = sub_bin_dos;
	}

	sub_bin_native = r_bin_pemixed_init_native (pe_bin);
	if (sub_bin_native) {
		bin->sub_bin_native = sub_bin_native;
	}
	sub_bin_net = pe_bin;
	bin->sub_bin_net = sub_bin_net;
	return true;
}

//carves out dos from original pe
//TODO: return mz file instead pe
struct PE_(r_bin_pe_obj_t)* r_bin_pemixed_init_dos(struct PE_(r_bin_pe_obj_t)* pe_bin) {
	ut8 * tmp_buf;

	ut64 pe_hdr_off = pe_bin->dos_header->e_lfanew;

	//idk if this is the most efficient way but could not find a function to read
	//RBuffer into another RBuffer
	if (!(tmp_buf = malloc (pe_hdr_off))) {
		return NULL;
	}

	if ((r_buf_read_at (pe_bin->b, 0, tmp_buf, pe_hdr_off)) == -1) {
		eprintf ("Error reading to buffer\n");
		return NULL;
	}

	struct PE_(r_bin_pe_obj_t)* sub_bin_dos = R_NEW0 (struct PE_(r_bin_pe_obj_t));
	if (!(sub_bin_dos->b = r_buf_new_with_bytes(tmp_buf, pe_hdr_off))) {
		PE_(r_bin_pe_free) (sub_bin_dos);
		return NULL;
	}

	sub_bin_dos->size = pe_hdr_off;
	sub_bin_dos->dos_header = pe_bin->dos_header;

	free (tmp_buf);
	return sub_bin_dos;
}

struct PE_(r_bin_pe_obj_t)* r_bin_pemixed_init_native(struct PE_(r_bin_pe_obj_t)* pe_bin) {
	ut8* zero_out;

	struct PE_(r_bin_pe_obj_t)* sub_bin_native = R_NEW0 (struct PE_(r_bin_pe_obj_t));
	memcpy (sub_bin_native, pe_bin, sizeof(struct PE_(r_bin_pe_obj_t)));

	//copy pe_bin->b and assign to sub_bin_native

	// if (!(tmp_buf = malloc (b_size))) {
	// 	eprintf("wtf malloc\n");
	// };

	// if (!(r_buf_read_at (pe_bin->b, 0, tmp_buf, b_size))) {
	// 	free (sub_bin_native);
	// 	return NULL;
	// }

	if (!(sub_bin_native->b = r_buf_new_with_buf(pe_bin->b))) {
		free (sub_bin_native);
		eprintf ("failed\n");
		return NULL;
	}

	//calculate the dotnet data directory offset
	int dotnet_offset = pe_bin->dos_header->e_lfanew;
	dotnet_offset += sizeof (PE_(image_nt_headers));
	dotnet_offset -= sizeof (PE_(image_data_directory)) * 2;

	if (!(zero_out = (ut8*) calloc (2, 4 * sizeof (ut8)))) {
		// can't call PE_(r_bin_pe_free) since this will free the underlying pe_bin
		// object which we may need for later
		// PE_(r_bin_pe_free) (sub_bin_native);
		r_buf_free (sub_bin_native->b);
		free (sub_bin_native);
		return NULL;
	}

	if (r_buf_write_at (sub_bin_native->b, dotnet_offset, zero_out, sizeof (PE_(image_data_directory))) < -1) {
		eprintf ("Zeroing out dotnet offset failed\n");
		r_buf_free (sub_bin_native->b);
		free (sub_bin_native);
		free (zero_out);
		return NULL;
	}

	free (zero_out);
	return sub_bin_native;
}

//this method should just return the original pe file
// struct PE_(r_bin_pe_obj_t)* r_bin_pemixed_init_net(struct PE_(r_bin_pe_obj_t)* pe_bin) {
//		return pe_bin;
// }

//not sure if this function is nessescary
struct PE_(r_bin_pe_obj_t)* r_bin_pemixed_extract(struct r_bin_pemixed_obj_t* bin, int sub_bin) {
	if (!bin) {
		return NULL;
	}

	switch (sub_bin) {
	case SUB_BIN_DOS:
		return bin->sub_bin_dos;
	case SUB_BIN_NATIVE:
		return bin->sub_bin_native;
	case SUB_BIN_NET:
		return bin->sub_bin_net;
	}
	return NULL;
}

//if IL only bit is set; if true then it is pure .NET binary with no unmanaged code
static bool check_il_only(ut32 flag) {
	ut32 check_mask = 1;
	return flag & check_mask;
}

void* r_bin_pemixed_free(struct r_bin_pemixed_obj_t* bin) {
	if (!bin) {
		return NULL;
	}
	//only one free is nessescary since they all point
	//to the same original pe struct
	//possible memleak here
	PE_(r_bin_pe_free)(bin->sub_bin_net);
	if (bin->sub_bin_dos) {
		r_buf_free (bin->sub_bin_dos->b); //dos is the only one with its own buf
	}
	free (bin->sub_bin_dos);
	free (bin->sub_bin_native);

	// PE_(r_bin_pe_free)(bin->sub_bin_native);
	// PE_(r_bin_pe_free)(bin->sub_bin_net);
	r_buf_free (bin->b);
	R_FREE(bin);
	return NULL;
}

struct r_bin_pemixed_obj_t * r_bin_pemixed_from_bytes_new(const ut8* buf, ut64 size) {
	struct r_bin_pemixed_obj_t* bin = R_NEW0 (struct r_bin_pemixed_obj_t);
	struct PE_(r_bin_pe_obj_t)* pe_bin;
	if (!bin || !buf) {
		return r_bin_pemixed_free (bin);
	}
	bin->b = r_buf_new_with_bytes (buf, size);
	if (!bin->b) {
		return r_bin_pemixed_free (bin);
	}
	bin->size = size;
	pe_bin = PE_(r_bin_pe_new_buf) (bin->b, true);
	if (!pe_bin) {
		PE_(r_bin_pe_free)(pe_bin);
		return r_bin_pemixed_free (bin);
	}
	if (!pe_bin->clr_hdr) {
		PE_(r_bin_pe_free) (pe_bin);
		return r_bin_pemixed_free (bin);
	}
	//check if binary only contains managed code
	//check implemented here cuz we need to intialize
	//the pe header to access the clr hdr
	if (check_il_only(pe_bin->clr_hdr->Flags)) {
		PE_(r_bin_pe_free) (pe_bin);
		return r_bin_pemixed_free (bin);
	}
	if (!r_bin_pemixed_init (bin, pe_bin)) {
		PE_(r_bin_pe_free) (pe_bin);
		return r_bin_pemixed_free (bin);
	}
	return bin;
}

