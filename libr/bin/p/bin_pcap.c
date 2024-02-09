/* radare - LGPL - Copyright 2017-2023 - srimantabarua, abcSup, pancake */

#include <r_bin.h>
#include <r_lib.h>

#include "../format/pcap/pcap.h"

#define CUSTOM_STRINGS 0

static RBinInfo *info(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	pcap_obj_t *obj = bf->bo->bin_obj;
	pcap_hdr_t *header = obj->header;
	ret->file = strdup (bf->file);
	ret->big_endian = true;
	ret->abi = strdup ("pcap");
	ret->type = strdup ("capture");
	ret->bclass = strdup ("tcpdump");
	ret->rclass = r_str_newf ("v%d.%d", header->version_major, header->version_minor);
	ret->flags = r_str_newf ("maxpktlen=%d", header->max_pkt_len);
	ret->os = strdup (pcap_network_string (header->network)); // , header->max_pkt_len);
	return ret;
}

static bool check(RBinFile *bf, RBuffer *b) {
	r_return_val_if_fail (b, false);

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
	r_return_val_if_fail (bf && buf, false);
	bf->bo->bin_obj = pcap_obj_new_buf (buf);
	return bf->bo->bin_obj != NULL;
}

static RList *symbols(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);

	RBinSymbol *ptr;
	pcap_obj_t *obj = bf->bo->bin_obj;
	ut64 size = r_buf_size (obj->b);
	if (size == 0 || size == UT64_MAX) {
		return NULL;
	}
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	// File header
	ptr = R_NEW0 (RBinSymbol);
	if (!ptr) {
		r_list_free (ret);
		return NULL;
	}
	ptr->name = r_bin_name_new_from (
		r_str_newf ("tcpdump capture file - version %d.%d (%s, capture length %"PFMT32u ")", obj->header->version_major,
			obj->header->version_minor, pcap_network_string (obj->header->network),
			obj->header->max_pkt_len)
		);
	ptr->paddr = ptr->vaddr = 0;
	r_list_append (ret, ptr);

	// Go through each record packet
	RListIter *iter;
	pcaprec_t *rec;
	switch (obj->header->network) {
	case LINK_ETHERNET:
		r_list_foreach (obj->recs, iter, rec) {
			pcaprec_ether_sym_add (ret, rec, rec->paddr + sizeof (pcaprec_hdr_t));
		}
		break;
	default:
		break;
	}
	return ret;
}

#if CUSTOM_STRINGS
static RList *strings(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);

	RBinString *ptr;
	pcap_obj_t *obj = bf->bo->bin_obj;
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	RListIter *iter;
	pcaprec_t *rec;
	r_list_foreach (obj->recs, iter, rec) {
		if (rec->data && *rec->data != 0) {
			ptr = R_NEW0 (RBinString);
			if (!ptr) {
				r_list_free (ret);
				return NULL;
			}
			ptr->string = r_str_ndup ((const char *)rec->data, 32); // rec->datasz);
			if (strlen (ptr->string) < 10) {
				// eprintf ("(%s)\n", ptr->string);
				free (ptr->string);
				free (ptr);
				continue;
			}
			ptr->paddr = ptr->vaddr = rec->paddr; //XXX;
			ptr->length = strlen (ptr->string);
			ptr->size = ptr->length + 1;
			ptr->type = R_STRING_TYPE_DETECT;
			r_list_append (ret, ptr);
		}
	}
	return ret;
}
#endif

static RList* libs(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);
	RList *ret = r_list_newf (free);
	if (ret) {
		r_list_append (ret, strdup ("ether"));
		r_list_append (ret, strdup ("tcp"));
		r_list_append (ret, strdup ("ipv4"));
		r_list_append (ret, strdup ("ipv6"));
	}
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

RBinPlugin r_bin_plugin_pcap = {
	.meta = {
		.name = "pcap",
		.desc = "libpcap/.pcap format",
		.license = "LGPL3",
		.author = "srimanta,pancake",
	},
	.info = info,
	.libs = libs,
	.baddr = baddr,
	.minstrlen = 16,
#if CUSTOM_STRINGS
	.strings = strings,
#endif
	.symbols = symbols,
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
