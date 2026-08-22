/* radare - LGPL - Copyright 2017-2026 - srimantabarua, abcSup, pancake */

#include <r_bin.h>
#include <r_lib.h>

#include "../format/pcap/pcap.h"

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

static void destroy(RBinFile *bf) {
	pcap_obj_free (bf->bo->bin_obj);
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
			n++;
			pcaprec_frame_sym_add (ret, rec, n);
			pcaprec_ether_sym_add (ret, rec, rec->paddr + sizeof (pcaprec_hdr_t));
		}
		break;
	default:
		break;
	}
	return true;
}

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

static void stream_print(RBin *bin, pcap_obj_t *obj, pcap_stream_t *s) {
	char *name = pcap_stream_name (s);
	bin->cb_printf ("%c %d %s pkts=%d a=%"PFMT64u" b=%"PFMT64u"\n", s->id == obj->cur? '*': ' ',
		s->id, name, r_list_length (s->recs), s->bytes[0], s->bytes[1]);
	free (name);
}

static void message_print(RBin *bin, pcaprec_t *rec) {
	bin->cb_printf ("0x%08"PFMT64x" %c %d\n", rec->dataoff, rec->dir? '<': '>', rec->datasz);
}

static bool stream_select(RBin *bin, pcap_obj_t *obj, int id) {
	pcap_stream_t *s = r_list_get_n (obj->streams, id);
	if (!s) {
		R_LOG_ERROR ("Invalid stream number");
		return false;
	}
	obj->cur = id;
	stream_print (bin, obj, s);
	return true;
}

// seek to the next or previous packet with payload in the stream of the current packet
static bool message_seek(RBin *bin, pcap_obj_t *obj, pcap_stream_t *s, bool next) {
	RIO *io = bin->iob.io;
	void *core = io? io->coreb.core: NULL;
	if (!core) {
		R_LOG_ERROR ("Seeking requires a core");
		return false;
	}
	ut64 addr = io->coreb.numGet (core, "$$");
	pcaprec_t *cur = pcap_rec_at (obj, addr);
	if (cur) {
		addr = cur->paddr;
		if (cur->stream) {
			s = cur->stream;
		}
	}
	if (!s) {
		R_LOG_ERROR ("No stream at the current offset");
		return true;
	}
	pcaprec_t *hit = NULL;
	RListIter *iter;
	pcaprec_t *rec;
	r_list_foreach (s->recs, iter, rec) {
		if (!rec->datasz) {
			continue;
		}
		if (rec->paddr > addr) {
			if (next) {
				hit = rec;
			}
			break;
		}
		if (rec->paddr < addr) {
			hit = rec;
		}
	}
	if (hit) {
		io->coreb.cmdf (core, "s 0x%"PFMT64x, hit->dataoff);
	} else {
		R_LOG_WARN ("No %s message in stream %d", next? "next": "previous", s->id);
	}
	return true;
}

static bool pcap_cmd(RBinFile *bf, const char *cmd) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj && cmd, false);
	pcap_obj_t *obj = bf->bo->bin_obj;
	RBin *bin = bf->rbin;
	pcap_stream_t *s = r_list_get_n (obj->streams, obj->cur);
	RListIter *iter;
	pcaprec_t *rec;
	switch (*cmd) {
	case 'n': // "i:n"
	case 'p': // "i:p"
		return message_seek (bin, obj, s, *cmd == 'n');
	case 's': // "i:s"
		if (cmd[1] != ' ' && !s) {
			R_LOG_ERROR ("No streams found");
			return false;
		}
		switch (cmd[1]) {
		case 0: // "i:s"
			r_list_foreach (obj->streams, iter, s) {
				stream_print (bin, obj, s);
			}
			return true;
		case ' ': // "i:s 3"
			return stream_select (bin, obj, r_num_math (NULL, cmd + 2));
		case '.': // "i:s."
			{
				RIO *io = bin->iob.io;
				rec = io && io->coreb.core? pcap_rec_at (obj, io->coreb.numGet (io->coreb.core, "$$")): NULL;
				if (!rec || !rec->stream) {
					R_LOG_ERROR ("No stream at the current offset");
					return false;
				}
				return stream_select (bin, obj, rec->stream->id);
			}
		case 'p': // "i:sp"
			r_list_foreach (s->recs, iter, rec) {
				if (rec->datasz) {
					message_print (bin, rec);
				}
			}
			return true;
		case 'a': // "i:sa"
		case 'b': // "i:sb"
			{
				ut64 len;
				ut8 *data = pcap_stream_data (obj, s, cmd[1] == 'b', &len);
				if (data && len > 0) {
					bin->consb.cb_write (bin->consb.cons, data, len);
				}
				free (data);
				return true;
			}
		}
		// fallthrough
	case 0:
	case '?':
		bin->cb_printf ("Usage: i:[snp]  reconstruct tcp/udp streams\n"
			"| i:s         list the streams, '*' marks the selected one\n"
			"| i:s <n>     select the stream number <n>\n"
			"| i:s.        select the stream of the packet at the current offset\n"
			"| i:sp        list the messages (payload offset, direction, size) of the selected stream\n"
			"| i:sa        dump the payload sent by the stream initiator (a -> b)\n"
			"| i:sb        dump the payload sent by the stream responder (b -> a)\n"
			"| i:n         seek to the next message in the stream of the current packet\n"
			"| i:p         seek to the previous message in the stream of the current packet\n");
		return true;
	}
	return false;
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
	.symbols_vec = symbols_vec,
	.cmd = pcap_cmd,
	.load = load,
	.destroy = destroy,
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
