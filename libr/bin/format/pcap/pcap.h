#ifndef _PCAP_H_
#define _PCAP_H_

#include <r_types.h>
#include <r_util.h>

// Magic number
#define	PCAP_MAGIC_LE       0xd4c3b2a1 // Magic number for pcap files
#define PCAP_MAGIC_BE       0xa1b2c3d4 // Magic number for pcap files
#define PCAP_NSEC_MAGIC_LE  0x4d3cb2a1 // Modified pcap with nsec resolution
#define PCAP_NSEC_MAGIC_BE  0xa1b23c4d // Modified pcap with nsec resolution
#define LIBPCAP_MAGIC       0xa1b2cd34// "libpcap" with Alexey Kuznetsoc's patches

#define LINK_NOLINK	0
#define LINK_ETHERNET	1
#define LINK_ETHERNET_3MB	2
#define LINK_AX_25	3
#define LINK_PRONET	4
#define LINK_CHAOS	5
#define LINK_TOKEN_RING	6
#define LINK_ARCNET	7
#define LINK_SLIP	8
#define LINK_PPP	9
#define LINK_FDDI	10
#define LINK_RFC_1483_ATM_1	11
#define LINK_RAW_IP_1	12
#define LINK_BSDOS_SLIP_1	13
#define LINK_BSDOS_PPP_1	14
#define LINK_LINUX_ATM_CLASSICAL_IP	19
#define LINK_PPP_CISCO_HDLC	50
#define LINK_PPP_OVER_ETHERNET	51
#define LINK_SYMANTEC_FIREWALL	99
#define LINK_RFC_1483_ATM_2	100
#define LINK_RAW_IP_2	101
#define LINK_BSDOS_SLIP_2	102
#define LINK_BSDOS_PPP_2	103
#define LINK_BSDOS_CISCO_HDLC	104
#define LINK_802_11	105
#define LINK_LINUX_CLASSICAL_IP_ATM	106
#define LINK_FRAME_RELAY	107
#define LINK_OPENBSD_LOOPBACK	108
#define LINK_OPENBSD_IPSEC_ENC	109
#define LINK_CISCO_HDLC	112
#define LINK_LINUX_COOKED	113
#define LINK_LOCALTALK	114
#define LINK_OPENBSD_PFLOG	117
#define LINK_802_11_PRISM	119
#define LINK_RFC_2625_IP_FIBRE_CHANNEL	122
#define LINK_SUNATM	123
#define LINK_802_11_RADIOTAP	127
#define LINK_LINUX_ARCNET	129
#define LINK_APPLE_IP_IEEE_1394	138
#define LINK_MTP2	140
#define LINK_MTP3	141
#define LINK_DOCSIS	143
#define LINK_IRDA	144
#define LINK_802_11_AVS_HDR	163

#define NET_IPV4 0x0800
#define NET_IPV6 0x86dd

#define TRANSPORT_TCP 6

// Global Header
typedef struct pcap_hdr_s {
	ut32 magic;			// magic number
	ut16 version_major;
	ut16 version_minor;
	st32 this_zone;		// GMT to local correction
	ut32 ts_accuracy;	// Accuracy of timestamps
	ut32 max_pkt_len;	// Max length of captured packets in bytes
	ut32 network;	// Data link type
} pcap_hdr_t;

// Ethernet header, always 14 bytes
typedef struct pcaprec_ether {
	ut8 dst[6];	// Destination MAC address
	ut8 src[6];	// Source MAC address
	ut16 type;
} pcaprec_ether_t;

// IPV4 header, atleast 20 bytes
typedef struct pcaprec_ipv4 {
	ut8  ver_len;	// Upper nibble = version, lower = header len in 4-byte words
	ut8  diff_serv;	// Differentiated services field
	ut16 tot_len;	// Total length of IPV4 packet
	ut16 id;
	ut16 flag_frag;	// Upper 3 bits = flags, lower 13 = fragment offset
	ut8  ttl;
	ut8  protocol;
	ut16 chksum;
	ut32 src;		// Source IP
	ut32 dst;		// Destination IP
} pcaprec_ipv4_t;

// IPV6 header
typedef struct pcaprec_ipv6 {
	ut32 vc_flow;   // version, class, flow
	ut16 plen;      // payload length
	ut8  nxt;       // next header
	ut8  hlim;      // hop limit
	ut8  src[16];   // source address
	ut8  dst[16];  // destination address
} pcaprec_ipv6_t;

// TCP header, 20 - 60 bytes
typedef struct pcaprec_tcp {
	ut16 src_port;	// Port on source
	ut16 dst_port;	// Port on destination
	ut32 seq_num;	// Sequence number
	ut32 ack_num;	// Ack number
	ut8  hdr_len;	// Length of TCP header
	ut16 flags;		// TCP flags
	ut16 win_sz;	// Window size
	ut16 chksum;
	ut16 urgnt_ptr;	// Urgent
	// Variable length options. Use hdr_len
} pcaprec_tcp_t;

// Record (Packet) Header
typedef struct pcaprec_hdr_s {
	ut32 ts_sec; // Timestamp in seconds
	ut32 ts_usec;	// Timestamp in usec (nanosec for PCAP_NSEC_MAGIC)
	ut32 incl_len;	// Length of packet captured
	ut32 orig_len;	// Original length of packet
} pcaprec_hdr_t;

typedef struct pcaprec_s {
	ut64 paddr;
	pcaprec_hdr_t *hdr;
	union {
		pcaprec_ether_t *ether_hdr;
	} link;
	union {
		pcaprec_ipv4_t *ipv4_hdr;
		pcaprec_ipv6_t *ipv6_hdr;
	} net;
	union {
		pcaprec_tcp_t *tcp_hdr;
	} transport;
	ut32 datasz;
	ut8 *data;
} pcaprec_t;

// The pcap object for RBinFile
typedef struct pcap_obj_s {
	pcap_hdr_t *header; // File header
	RList/*<pcaprec_t>*/ *recs;
	bool is_nsec; // nsec timestamp resolution?
	bool bigendian;
	RBuffer *b;
} pcap_obj_t;

pcap_obj_t *pcap_obj_new_buf(RBuffer *buf);
void pcap_obj_free (pcap_obj_t *obj);
void pcaprec_free(pcaprec_t *rec);
void pcaprec_ether_sym_add(RList *list, pcaprec_t *rec, ut64 paddr);
const char* pcap_network_string(ut32 network);
const char *ipv6_addr_string (ut8 *addr);

#endif  // _PCAP_H_
