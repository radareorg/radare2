/* radare2 - LGPL - Copyright 2017-2019 - wargio */

#include <r_util.h>
#include <r_cons.h>

typedef float  ft32;
typedef double ft64;

#define WIRE_VARINT    0 // int32, int64, uint32, uint64, sint32, sint64, bool, enum
#define WIRE_64_BIT    1 // fixed64, sfixed64, double
#define WIRE_LEN_DELIM 2 // string, bytes, embedded messages, packed repeated fields
#define WIRE_START_GRP 3 // groups (deprecated)
#define WIRE_END_GRP   4 // groups (deprecated)
#define WIRE_32_BIT    5 // fixed32, sfixed32, float

typedef R_PACKED (struct _proto_head {
	ut8 wire   : 3;
	ut8 number : 5;
}) proto_head_t;

static const char* s_wire(const ut8 byte) {
	switch (byte) {
	case WIRE_VARINT:
		return "[VARINT]";
	case WIRE_64_BIT:
		return "[64_BIT]";
	case WIRE_LEN_DELIM:
		return "[LEN_DELIM]";
	case WIRE_START_GRP:
		return "[START_GROUP]";
	case WIRE_END_GRP:
		return "[END_GROUP]";
	case WIRE_32_BIT:
		return "[32_BIT]";
	default:
		return "[UNKN]";
	}
}

static void pad(RStrBuf *sb, ut32 count) {
	ut32 i;
	for (i = 0; i < count; i++) {
		r_strbuf_appendf (sb, "    ");
	}
}

static bool is_string(const ut8* start, const ut8* end) {
	while (start < end) {
		// TODO UTF-8 Support.
		if (!IS_PRINTABLE (*start)) {
			return false;
		}
		start++;
	}
	return true;
}

static void decode_array(RStrBuf *sb, const ut8* start, const ut8* end) {
	while (start < end) {
		r_strbuf_appendf (sb, "%02x ", *start);
		start++;
	}
	r_strbuf_appendf (sb, "\n");
}

static void decode_buffer(RStrBuf *sb, const ut8* start, const ut8* end, ut32 padcnt, bool debug) {
	size_t bytes_read = 0;
	ut32 var32 = 0;
	ut64 var64 = 0;
	const ut8* buffer = start;
	const proto_head_t *h = NULL;
	while(buffer >= start && buffer < end) {
		if (!*buffer) {
			return;
		}
		//ut8 byte = *buffer;
		h = (proto_head_t*) buffer;
		buffer++;
		if (buffer < start || buffer >= end) {
			eprintf ("\ninvalid buffer pointer.\n");
			break;
		} else if (h->wire > WIRE_32_BIT) {
			eprintf ("\nunknown wire id (%u).\n", h->wire);
			return;
		}
		if (h->wire != WIRE_END_GRP) {
			pad (sb, padcnt);
			if (debug) {
				r_strbuf_appendf (sb, "%u %-13s", h->number, s_wire(h->wire));
			} else {
				r_strbuf_appendf (sb, "%u", h->number);
			}
		}
		switch(h->wire) {
		case WIRE_VARINT:
			{
				st64* i = (st64*) &var64;
				bytes_read = read_u64_leb128 (buffer, end, &var64);
				r_strbuf_appendf (sb, ": %"PFMT64u" | %"PFMT64d"\n", var64, *i);
			}
			break;
		case WIRE_64_BIT:
			{
				ft64* f = (ft64*) &var64;
				st64* i = (st64*) &var64;
				bytes_read = read_u64_leb128 (buffer, end, &var64);
				r_strbuf_appendf (sb, ": %"PFMT64u" | %"PFMT64d" | %f\n", var64, *i, *f);
			}
			break;
		case WIRE_LEN_DELIM:
			{
				bytes_read = read_u64_leb128 (buffer, end, &var64);
				const ut8* ps = buffer + bytes_read;
				const ut8* pe = ps + var64;
				if (ps > buffer && pe <= end) {
					if (is_string (ps, pe)) {
						r_strbuf_appendf (sb, ": \"%.*s\"\n", var64, (const char*) ps);
					} else {
						r_strbuf_appendf (sb, " {\n");
						decode_buffer (sb, ps, pe, padcnt + 1, debug);
						pad (sb, padcnt);
						r_strbuf_appendf (sb, "}\n");
					}
					bytes_read += var64;
				} else {
					eprintf ("\ninvalid delimited length (%"PFMT64u").\n", var64);
					return;
				}
			}
			break;
		case WIRE_START_GRP:
			r_strbuf_appendf (sb, " {\n");
			padcnt++;
			break;
		case WIRE_END_GRP:
			if (padcnt > 1) {
				padcnt--;
			}
			pad (sb, padcnt);
			r_strbuf_appendf (sb, "}\n");
			break;
		case WIRE_32_BIT:
			{
				ft32* f = (ft32*) &var32;
				st32* i = (st32*) &var32;
				bytes_read = read_u32_leb128 (buffer, end, &var32);
				r_strbuf_appendf (sb, ": %u | %d | %f\n", var32, *i, *f);
			}
			break;
		default:
			decode_array (sb, buffer - 1, end);
			return;
		}
		buffer += bytes_read;
	}
}

R_API char *r_protobuf_decode(const ut8* start, const ut64 size, bool debug) {
	if (!start || !size) {
		eprintf ("Invalid buffer pointer or size.\n");
		return NULL;
	}
	const ut8* end = start + size;
	RStrBuf *sb = r_strbuf_new ("");
	decode_buffer (sb, start, end, 0u, debug);
	return r_strbuf_drain (sb);
}
