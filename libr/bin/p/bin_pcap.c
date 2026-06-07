/* radare - LGPL - Copyright 2017-2025 - srimantabarua, abcSup, pancake */

#include <r_bin.h>
#include <r_lib.h>

#include "../format/pcap/pcap.h"

#define CUSTOM_STRINGS 0

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	pcap_obj_t *obj = bf->bo->bin_obj;
	pcap_hdr_t *header = obj->header;
	ret->file = strdup (bf->file);
	ret->big_endian = obj->bigendian;
	ret->abi = strdup ("pcap");
	ret->type = strdup ("capture");
	ret->bclass = strdup ("tcpdump");
	ret->rclass = r_str_newf ("v%d.%d", header->version_major, header->version_minor);
	ret->flags = r_str_newf ("maxpktlen=%d", header->max_pkt_len);
	ret->os = strdup (pcap_network_string (header->network)); // , header->max_pkt_len);
	return ret;
}

static bool check(RBinFile *bf, RBuffer *b) {
	R_RETURN_VAL_IF_FAIL (b, false);

	switch (r_buf_read_be32_at (b, 0)) {
	case PCAP_MAGIC_LE:
	case PCAP_MAGIC_BE:
	case PCAP_NSEC_MAGIC_LE:
	case PCAP_NSEC_MAGIC_BE:
		return true;
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && buf, false);
	bf->bo->bin_obj = pcap_obj_new_buf (buf);
	return bf->bo->bin_obj != NULL;
}

static bool symbols_vec(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, false);

	pcap_obj_t *obj = bf->bo->bin_obj;
	ut64 size = r_buf_size (obj->b);
	if (size == 0 || size == UT64_MAX) {
		return false;
	}
	RVecRBinSymbol *ret = &bf->bo->symbols_vec;

	// File header
	RBinSymbol *ptr = RVecRBinSymbol_emplace_back (ret);
	ptr->name = r_bin_name_new_from (
		r_str_newf ("tcpdump capture file - version %d.%d (%s, capture length %"PFMT32u ")", obj->header->version_major,
			obj->header->version_minor, pcap_network_string (obj->header->network),
			obj->header->max_pkt_len)
		);
	ptr->paddr = ptr->vaddr = 0;

	// Go through each record packet
	RListIter *iter;
	pcaprec_t *rec;
	int n = 0;
	switch (obj->header->network) {
	case LINK_ETHERNET:
		r_list_foreach (obj->recs, iter, rec) {
			pcaprec_frame_sym_add (ret, rec, ++n);
			pcaprec_ether_sym_add (ret, rec, rec->paddr + sizeof (pcaprec_hdr_t));
		}
		break;
	default:
		break;
	}
	return true;
}

#if CUSTOM_STRINGS
static RVecRBinString *strings(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);

	pcap_obj_t *obj = bf->bo->bin_obj;
	RVecRBinString *ret = RVecRBinString_new ();

	RListIter *iter;
	pcaprec_t *rec;
	r_list_foreach (obj->recs, iter, rec) {
		if (rec->data && *rec->data != 0) {
			RBinString *ptr = RVecRBinString_emplace_back (ret);
			if (!ptr) {
				break;
			}
			ptr->string = r_str_ndup ((const char *)rec->data, 32); // rec->datasz);
			if (strlen (ptr->string) < 10) {
				// eprintf ("(%s)\n", ptr->string);
				RVecRBinString_pop_back (ret);
				continue;
			}
			ptr->paddr = ptr->vaddr = rec->paddr; //XXX;
			ptr->length = strlen (ptr->string);
			ptr->size = ptr->length + 1;
			ptr->type = R_STRING_TYPE_DETECT;
		}
	}
	return ret;
}
#endif

static RList* libs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RList *ret = r_list_newf (free);
	r_list_append (ret, strdup ("ether"));
	r_list_append (ret, strdup ("tcp"));
	r_list_append (ret, strdup ("ipv4"));
	r_list_append (ret, strdup ("ipv6"));
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

RBinPlugin r_bin_plugin_pcap = {
	.meta = {
		.name = "pcap",
		.desc = "Packet Capture Network Analysis container",
		.license = "LGPL-3.0-only",
		.author = "srimanta,pancake",
	},
	.info = info,
	.libs = libs,
	.baddr = baddr,
	.minstrlen = 16,
#if CUSTOM_STRINGS
	.strings = strings,
#endif
	.symbols_vec = symbols_vec,
	.load= load,
	.check = check,
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pcap,
	.version = R2_VERSION,
	.pkgname = "pcap"
};
#endif
