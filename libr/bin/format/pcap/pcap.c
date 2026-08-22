#include <r_bin.h>

#include "pcap.h"

void pcap_obj_free(pcap_obj_t *obj) {
	if (obj) {
		free (obj->header);
		r_list_free (obj->recs);
		r_list_free (obj->streams);
		r_unref (obj->b);
		free (obj);
	}
}

static bool pcap_obj_init_hdr(pcap_obj_t *obj) {
	pcap_hdr_t *hdr = R_NEW0 (pcap_hdr_t);
	hdr->magic = r_buf_read_ble32_at (obj->b, 0, obj->bigendian);
	hdr->version_major = r_buf_read_ble16_at (obj->b, 4, obj->bigendian);
	hdr->version_minor = r_buf_read_ble16_at (obj->b, 6, obj->bigendian);
	hdr->this_zone = r_buf_read_ble32_at (obj->b, 8, obj->bigendian);
	hdr->ts_accuracy = r_buf_read_ble32_at (obj->b, 12, obj->bigendian);
	hdr->max_pkt_len = r_buf_read_ble32_at (obj->b, 16, obj->bigendian);
	hdr->network = r_buf_read_ble32_at (obj->b, 20, obj->bigendian);
	obj->header = hdr;
	return true;
}

void pcaprec_free(pcaprec_t *rec) {
	if (rec) {
		free (rec->hdr);
		free (rec->link.ether_hdr);
		free (rec->net.ipv4_hdr);
		free (rec);
	}
}

// end of the captured bytes of this record
static ut64 rec_end(pcaprec_t *rec) {
	return rec->paddr + sizeof (pcaprec_hdr_t) + rec->hdr->incl_len;
}

static void parse_tcp(RBuffer *b, ut64 off, pcaprec_t *rec, ut32 size) {
	ut8 buf[20];
	if (size < sizeof (buf) || r_buf_read_at (b, off, buf, sizeof (buf)) != sizeof (buf)) {
		return;
	}
	ut32 hdrlen = (buf[12] >> 4) * 4;
	if (hdrlen < sizeof (buf) || hdrlen > size) {
		return;
	}
	rec->proto = TRANSPORT_TCP;
	rec->sport = r_read_at_be16 (buf, 0);
	rec->dport = r_read_at_be16 (buf, 2);
	rec->seq = r_read_at_be32 (buf, 4);
	rec->dataoff = off + hdrlen;
	rec->datasz = size - hdrlen;
}

static void parse_udp(RBuffer *b, ut64 off, pcaprec_t *rec, ut32 size) {
	ut8 buf[8];
	if (size < sizeof (buf) || r_buf_read_at (b, off, buf, sizeof (buf)) != sizeof (buf)) {
		return;
	}
	ut32 len = R_MIN (r_read_at_be16 (buf, 4), size);
	if (len < sizeof (buf)) {
		return;
	}
	rec->proto = TRANSPORT_UDP;
	rec->sport = r_read_at_be16 (buf, 0);
	rec->dport = r_read_at_be16 (buf, 2);
	rec->dataoff = off + sizeof (buf);
	rec->datasz = len - sizeof (buf);
}

static void parse_transport(RBuffer *b, ut64 off, pcaprec_t *rec, ut8 proto, ut32 size) {
	ut64 end = rec_end (rec);
	if (off >= end) {
		return;
	}
	size = R_MIN (size, end - off);
	switch (proto) {
	case TRANSPORT_TCP:
		parse_tcp (b, off, rec, size);
		break;
	case TRANSPORT_UDP:
		parse_udp (b, off, rec, size);
		break;
	}
}

static bool parse_ipv4(RBuffer *b, ut64 off, pcaprec_t *rec) {
	ut8 buf[sizeof (pcaprec_ipv4_t)] = {0};
	pcaprec_ipv4_t *ipv4 = R_NEW0 (pcaprec_ipv4_t);
	r_buf_read_at (b, off, buf, sizeof (buf));
	ipv4->ver_len = r_read_at_be8 (buf, 0);
	ipv4->diff_serv = r_read_at_be8 (buf, 1);
	ipv4->tot_len = r_read_at_be16 (buf, 2);
	ipv4->id = r_read_at_be16 (buf, 4);
	ipv4->flag_frag = r_read_at_be16 (buf, 6);
	ipv4->ttl = r_read_at_be8 (buf, 8);
	ipv4->protocol = r_read_at_be8 (buf, 9);
	ipv4->chksum = r_read_at_be16 (buf, 10);
	ipv4->src = r_read_at_be32 (buf, 12);
	ipv4->dst = r_read_at_be32 (buf, 16);

	ut32 hdrlen = (ipv4->ver_len & 0x0F) * 4;
	if (hdrlen >= sizeof (buf) && ipv4->tot_len >= hdrlen) {
		parse_transport (b, off + hdrlen, rec, ipv4->protocol, ipv4->tot_len - hdrlen);
	}
	rec->net.ipv4_hdr = ipv4;
	return true;
}

static bool parse_ipv6(RBuffer *b, ut64 off, pcaprec_t *rec) {
	pcaprec_ipv6_t *ipv6 = R_NEW0 (pcaprec_ipv6_t);
	ut8 buf[sizeof (pcaprec_ipv6_t)] = { 0 };
	r_buf_read_at (b, off, (ut8*)buf, sizeof (pcaprec_ipv6_t));
	ipv6->vc_flow = r_read_at_be32 (buf, 0);
	ipv6->plen = r_read_at_be16 (buf, 4);
	ipv6->nxt = buf[6];
	ipv6->hlim = buf[7];
	memcpy (ipv6->src, buf + 8, 16);
	memcpy (ipv6->dst, buf + 24, 16);
	parse_transport (b, off + sizeof (pcaprec_ipv6_t), rec, ipv6->nxt, ipv6->plen);
	rec->v6 = true;
	rec->net.ipv6_hdr = ipv6;
	return true;
}

static bool parse_ether(RBuffer *b, ut64 off, pcaprec_t *rec) {
	pcaprec_ether_t *ether = R_NEW0 (pcaprec_ether_t);
	// dst 6 bytes
	// src 6 bytes
	r_buf_read_at (b, off, (ut8*)ether, sizeof (pcaprec_ether_t));
	ut64 next = off + sizeof (pcaprec_ether_t);
	ether->type = r_read_at_be16 (ether, 12);
	switch (ether->type) {
	case NET_IPV4:
		if (!parse_ipv4 (b, next, rec)) {
			return false;
		}
		break;
	case NET_IPV6:
		if (!parse_ipv6 (b, next, rec)) {
			return false;
		}
		break;
	default:
		break;
	}
	rec->link.ether_hdr = ether;
	return true;
}

static bool pcap_obj_init_recs(pcap_obj_t *obj) {
	RBuffer *b = obj->b;
	ut64 off = sizeof (pcap_hdr_t);
	ut64 size = r_buf_size (obj->b);
	if (size == 0 || size == UT64_MAX) {
		return false;
	}
	RList *recs = r_list_newf ((RListFree)pcaprec_free);
	if (!recs) {
		return false;
	}

	while (off < size) {
		ut64 rec_off = off;
		pcaprec_hdr_t *rec_hdr = R_NEW0 (pcaprec_hdr_t);
		rec_hdr->ts_sec = r_buf_read_ble32_at (obj->b, off, obj->bigendian);
		rec_hdr->ts_usec = r_buf_read_ble32_at (obj->b, off + 4, obj->bigendian);
		rec_hdr->incl_len = r_buf_read_ble32_at (obj->b, off + 8, obj->bigendian);
		rec_hdr->orig_len = r_buf_read_ble32_at (obj->b, off + 12, obj->bigendian);
		ut64 pkt_off = off + sizeof (pcaprec_hdr_t);
		if (pkt_off + rec_hdr->incl_len > size) {
			free (rec_hdr);
			goto error;
		}

		pcaprec_t *rec = R_NEW0 (pcaprec_t);
		rec->paddr = rec_off;
		rec->hdr = rec_hdr;

		bool itsok = true;
		switch (obj->header->network) {
		case LINK_ETHERNET:
			if (!parse_ether (b, pkt_off, rec)) {
				itsok = false;
				// ignore errors here	return false;
			}
			break;
		default:
			break;
		}
		if (itsok) {
			r_list_append (recs, rec);
		} else {
			pcaprec_free (rec);
		}
		off = pkt_off + rec_hdr->incl_len;
	}
	obj->recs = recs;
	return true;
error:
	r_list_free (recs);
	return false;
}

static void pcap_stream_free(pcap_stream_t *s) {
	if (s) {
		r_list_free (s->recs);
		free (s);
	}
}

// endpoint as 16 byte address + 2 byte port, so they can be compared with memcmp
static void rec_endpoint(pcaprec_t *rec, bool dst, ut8 *ep) {
	memset (ep, 0, 16);
	if (rec->v6) {
		memcpy (ep, dst? rec->net.ipv6_hdr->dst: rec->net.ipv6_hdr->src, 16);
	} else {
		r_write_be32 (ep, dst? rec->net.ipv4_hdr->dst: rec->net.ipv4_hdr->src);
	}
	r_write_be16 (ep + 16, dst? rec->dport: rec->sport);
}

static bool pcap_obj_init_streams(pcap_obj_t *obj) {
	obj->streams = r_list_newf ((RListFree)pcap_stream_free);
	HtPP *ht = ht_pp_new0 ();
	if (!obj->streams || !ht) {
		ht_pp_free (ht);
		return false;
	}
	RListIter *iter;
	pcaprec_t *rec;
	r_list_foreach (obj->recs, iter, rec) {
		if (!rec->proto) {
			continue;
		}
		ut8 ep[2][18];
		rec_endpoint (rec, false, ep[0]);
		rec_endpoint (rec, true, ep[1]);
		// the key orders the endpoints, so both directions map to the same stream
		int lo = memcmp (ep[0], ep[1], sizeof (ep[0])) > 0;
		ut8 raw[1 + sizeof (ep)] = { rec->proto };
		memcpy (raw + 1, ep[lo], sizeof (ep[0]));
		memcpy (raw + 1 + sizeof (ep[0]), ep[!lo], sizeof (ep[0]));
		char key[sizeof (raw) * 2 + 1];
		r_hex_bin2str (raw, sizeof (raw), key);
		pcap_stream_t *s = ht_pp_find (ht, key, NULL);
		if (!s) {
			s = R_NEW0 (pcap_stream_t);
			s->id = r_list_length (obj->streams);
			s->proto = rec->proto;
			s->v6 = rec->v6;
			memcpy (s->ip[0], ep[0], 16);
			memcpy (s->ip[1], ep[1], 16);
			s->port[0] = rec->sport;
			s->port[1] = rec->dport;
			s->recs = r_list_new ();
			r_list_append (obj->streams, s);
			ht_pp_insert (ht, key, s);
		}
		rec->stream = s;
		rec->dir = memcmp (ep[0], s->ip[0], 16) || rec->sport != s->port[0];
		s->bytes[rec->dir] += rec->datasz;
		r_list_append (s->recs, rec);
	}
	ht_pp_free (ht);
	return true;
}

static bool pcap_obj_init(pcap_obj_t *obj) {
	switch (r_buf_read_be32_at (obj->b, 0)) {
	case PCAP_MAGIC_LE:
		obj->bigendian = false;
		obj->is_nsec = false;
		break;
	case PCAP_MAGIC_BE:
		obj->bigendian = true;
		obj->is_nsec = false;
		break;
	case PCAP_NSEC_MAGIC_LE:
		obj->bigendian = false;
		obj->is_nsec = true;
		break;
	case PCAP_NSEC_MAGIC_BE:
		obj->bigendian = true;
		obj->is_nsec = true;
		break;
	default:
		return false;
	}
	return pcap_obj_init_hdr (obj) && pcap_obj_init_recs (obj) && pcap_obj_init_streams (obj);
}

pcap_obj_t *pcap_obj_new_buf(RBuffer *buf) {
	R_RETURN_VAL_IF_FAIL (buf, NULL);

	pcap_obj_t *obj = R_NEW0 (pcap_obj_t);
	obj->b = r_ref (buf);
	if (!pcap_obj_init (obj)) {
		pcap_obj_free (obj);
		return NULL;
	}
	return obj;
}

void pcaprec_frame_sym_add(RVecRBinSymbol *vec, pcaprec_t *rec, int n) {
	RBinSymbol *ptr = RVecRBinSymbol_emplace_back (vec);
	ptr->name = r_bin_name_new_from (r_str_newf ("0x%"PFMT64x": Frame %d, %"PFMT32u " bytes on wire, %"PFMT32u " bytes captured",
		rec->paddr, n, rec->hdr->orig_len, rec->hdr->incl_len));
	ptr->paddr = ptr->vaddr = rec->paddr;
}

static void pcaprec_transport_sym_add(RVecRBinSymbol *vec, pcaprec_t *rec, ut64 paddr) {
	const char *name;
	switch (rec->proto) {
	case TRANSPORT_TCP:
		name = "Transmission Control Protocol";
		break;
	case TRANSPORT_UDP:
		name = "User Datagram Protocol";
		break;
	default:
		return;
	}
	RBinSymbol *ptr = RVecRBinSymbol_emplace_back (vec);
	ptr->name = r_bin_name_new_from (r_str_newf ("0x%"PFMT64x": %s, Src Port: %d, Dst"
		" port: %d, Len: %d", paddr, name, rec->sport, rec->dport, rec->datasz));
	ptr->paddr = ptr->vaddr = paddr;
}

static void pcaprec_ipv4_sym_add(RVecRBinSymbol *vec, pcaprec_t* rec, ut64 paddr) {
	pcaprec_ipv4_t *ipv4 = rec->net.ipv4_hdr;
	RBinSymbol *ptr = RVecRBinSymbol_emplace_back (vec);
	ptr->name = r_bin_name_new_from (r_str_newf ("0x%"PFMT64x": IPV%d, Src: %d.%d.%d.%d, Dst: %d.%d.%d.%d",
		paddr, (ipv4->ver_len >> 4) & 0x0F,
	(ipv4->src >> 24) & 0xFF, (ipv4->src >> 16) & 0xFF,
	(ipv4->src >> 8) & 0xFF, ipv4->src & 0xFF,
	(ipv4->dst >> 24) & 0xFF, (ipv4->dst >> 16) & 0xFF,
	(ipv4->dst >> 8) & 0xFF, ipv4->dst & 0xFF));
	ptr->paddr = ptr->vaddr = paddr;
	pcaprec_transport_sym_add (vec, rec, paddr + ((ipv4->ver_len & 0x0F) * 4));
}

static char *ipv6_addr_string(const ut8 *addr) {
	ut16 words[8];
	int i, start = -1, len = 0, maxlen = 0;
	// find the longest run of zero words, rfc5952 replaces it with "::"
	for (i = 0; i < 8; i++) {
		words[i] = r_read_at_be16 (addr, i * 2);
		len = words[i]? 0: len + 1;
		if (len > maxlen) {
			maxlen = len;
			start = i - len + 1;
		}
	}
	if (maxlen < 2) {
		start = -1;
	}
	RStrBuf *sb = r_strbuf_new ("");
	for (i = 0; i < 8; i++) {
		if (i == start) {
			r_strbuf_append (sb, "::");
			i += maxlen - 1;
		} else {
			r_strbuf_appendf (sb, "%s%x", (i > 0 && i != start + maxlen)? ":": "", words[i]);
		}
	}
	return r_strbuf_drain (sb);
}

static void pcaprec_ipv6_sym_add(RVecRBinSymbol *vec, pcaprec_t* rec, ut64 paddr) {
	pcaprec_ipv6_t *ipv6 = rec->net.ipv6_hdr;
	char *src = ipv6_addr_string (ipv6->src);
	char *dst = ipv6_addr_string (ipv6->dst);
	RBinSymbol *ptr = RVecRBinSymbol_emplace_back (vec);
	ptr->name = r_bin_name_new_from (r_str_newf ("0x%"PFMT64x": IPV6, Src: %s, Dst: %s", paddr, src, dst));
	ptr->paddr = ptr->vaddr = paddr;
	free (src);
	free (dst);
	pcaprec_transport_sym_add (vec, rec, paddr + sizeof (pcaprec_ipv6_t));
}

void pcaprec_ether_sym_add(RVecRBinSymbol *vec, pcaprec_t *rec, ut64 paddr) {
	pcaprec_ether_t *ether = rec->link.ether_hdr;
	if (!ether) {
		return;
	}
	RBinSymbol *ptr = RVecRBinSymbol_emplace_back (vec);
	ptr->name = r_bin_name_new_from (r_str_newf ("0x%"PFMT64x": Ethernet, Src: %02"PFMT32x ":%02"PFMT32x ":%02"PFMT32x
		":%02"PFMT32x ":%02"PFMT32x ":%02"PFMT32x ", Dst: %02"PFMT32x
		":%02"PFMT32x ":%02"PFMT32x ":%02"PFMT32x ":%02"PFMT32x ":%02"PFMT32x,
		paddr, ether->src[0], ether->src[1], ether->src[2], ether->src[3], ether->src[4], ether->src[5],
		ether->dst[0], ether->dst[1], ether->dst[2], ether->dst[3], ether->dst[4], ether->dst[5]));
	ptr->paddr = ptr->vaddr = paddr;

	switch (ether->type) {
	case NET_IPV4:
		pcaprec_ipv4_sym_add (vec, rec, paddr + sizeof (pcaprec_ether_t));
		break;
	case NET_IPV6:
		pcaprec_ipv6_sym_add (vec, rec, paddr + sizeof (pcaprec_ether_t));
		break;
	default:
		break;
	}
}

const char* pcap_network_string(ut32 network) {
	switch (network) {
	case LINK_NOLINK:
		return "No link-layer encapsulation";
	case LINK_ETHERNET:
		return "Ethernet";
	case LINK_ETHERNET_3MB:
		return "3Mb Ethernet";
	case LINK_AX_25:
		return "AX.25";
	case LINK_PRONET:
		return "ProNET";
	case LINK_CHAOS:
		return "CHAOS";
	case LINK_TOKEN_RING:
		return "Token Ring";
	case LINK_ARCNET:
		return "ARCNET";
	case LINK_SLIP:
		return "SLIP";
	case LINK_PPP:
		return "PPP";
	case LINK_FDDI:
		return "FDDI";
	case LINK_RFC_1483_ATM_1:
	case LINK_RFC_1483_ATM_2:
		return "RFC 1483 ATM";
	case LINK_RAW_IP_1:
	case LINK_RAW_IP_2:
		return "raw IP";
	case LINK_BSDOS_SLIP_1:
	case LINK_BSDOS_SLIP_2:
		return "BSD/OS SLIP";
	case LINK_BSDOS_PPP_1:
	case LINK_BSDOS_PPP_2:
		return "BSD/OS PPP";
	case LINK_LINUX_ATM_CLASSICAL_IP:
		return "Linux ATM Classical IP";
	case LINK_PPP_CISCO_HDLC:
		return "PPP or Cisco HDLC";
	case LINK_PPP_OVER_ETHERNET:
		return "PPP-over-Ethernet";
	case LINK_SYMANTEC_FIREWALL:
		return "Symantec Enterprise Firewall";
	case LINK_BSDOS_CISCO_HDLC:
		return "BSD/OS Cisco HDLC";
	case LINK_802_11:
		return "802.11";
	case LINK_LINUX_CLASSICAL_IP_ATM:
		return "Linux Classical IP over ATM";
	case LINK_FRAME_RELAY:
		return "Frame Relay";
	case LINK_OPENBSD_LOOPBACK:
		return "OpenBSD loopback";
	case LINK_OPENBSD_IPSEC_ENC:
		return "OpenBSD IPsec encrypted";
	case LINK_CISCO_HDLC:
		return "Cisco HDLC";
	case LINK_LINUX_COOKED:
		return "Linux \"cooked\"";
	case LINK_LOCALTALK:
		return "LocalTalk";
	case LINK_OPENBSD_PFLOG:
		return "OpenBSD PFLOG";
	case LINK_802_11_PRISM:
		return "802.11 with Prism header";
	case LINK_RFC_2625_IP_FIBRE_CHANNEL:
		return "RFC 2625 over Fibre Channel";
	case LINK_SUNATM:
		return "SunATM";
	case LINK_802_11_RADIOTAP:
		return "802.11 with radiotap header";
	case LINK_LINUX_ARCNET:
		return "Linux ARCNET";
	case LINK_APPLE_IP_IEEE_1394:
		return "Apple IP over IEEE 1394";
	case LINK_MTP2:
		return "MTP2";
	case LINK_MTP3:
		return "MTP3";
	case LINK_DOCSIS:
		return "DOCSIS";
	case LINK_IRDA:
		return "IrDA";
	case LINK_802_11_AVS_HDR:
		return "802.11 with AVS header";
	default:
		return "Unknown";
	}
}

pcaprec_t *pcap_rec_at(pcap_obj_t *obj, ut64 addr) {
	RListIter *iter;
	pcaprec_t *rec;
	r_list_foreach (obj->recs, iter, rec) {
		if (addr >= rec->paddr && addr < rec_end (rec)) {
			return rec;
		}
	}
	return NULL;
}

static char *endpoint_string(pcap_stream_t *s, int ep) {
	const ut8 *ip = s->ip[ep];
	if (s->v6) {
		char *a = ipv6_addr_string (ip);
		char *r = r_str_newf ("[%s]:%d", a, s->port[ep]);
		free (a);
		return r;
	}
	return r_str_newf ("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], s->port[ep]);
}

char *pcap_stream_name(pcap_stream_t *s) {
	char *a = endpoint_string (s, 0);
	char *b = endpoint_string (s, 1);
	char *r = r_str_newf ("%s %s -> %s", s->proto == TRANSPORT_TCP? "tcp": "udp", a, b);
	free (a);
	free (b);
	return r;
}

// payload sent in one direction, tcp retransmissions are dropped and overlaps trimmed
ut8 *pcap_stream_data(pcap_obj_t *obj, pcap_stream_t *s, int dir, ut64 *len) {
	ut8 *buf = malloc (s->bytes[dir] + 1);
	if (!buf) {
		return NULL;
	}
	ut64 n = 0;
	ut32 next = 0;
	bool first = true;
	RListIter *iter;
	pcaprec_t *rec;
	r_list_foreach (s->recs, iter, rec) {
		if (rec->dir != dir || !rec->datasz) {
			continue;
		}
		ut64 off = rec->dataoff;
		ut32 sz = rec->datasz;
		if (s->proto == TRANSPORT_TCP) {
			if (first) {
				next = rec->seq;
				first = false;
			}
			st32 delta = (st32)(rec->seq - next);
			if (delta < 0) {
				if ((ut32)-delta >= sz) {
					continue;
				}
				off -= delta;
				sz += delta;
			}
			if ((st32)(rec->seq + rec->datasz - next) > 0) {
				next = rec->seq + rec->datasz;
			}
		}
		st64 r = r_buf_read_at (obj->b, off, buf + n, sz);
		if (r > 0) {
			n += r;
		}
	}
	buf[n] = 0;
	*len = n;
	return buf;
}
