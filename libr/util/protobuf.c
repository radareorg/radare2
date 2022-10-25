/* radare2 - LGPL - Copyright 2017-2019 - wargio */

#include <r_util.h>
#include <r_cons.h>
#include <r_util/pj.h>

typedef float ft32;
typedef double ft64;

#define WIRE_VARINT    0 // int32, int64, uint32, uint64, sint32, sint64, bool, enum
#define WIRE_64_BIT    1 // fixed64, sfixed64, double
#define WIRE_LEN_DELIM 2 // string, bytes, embedded messages, packed repeated fields
#define WIRE_START_GRP 3 // groups (deprecated)
#define WIRE_END_GRP   4 // groups (deprecated)
#define WIRE_32_BIT    5 // fixed32, sfixed32, float

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

static void pad(RStrBuf *sb, int count) {
	int i;
	for (i = 0; i < count; i++) {
		r_strbuf_append (sb, "    ");
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

static char *decode_array(const ut8* start, const ut8* end) {
	RStrBuf *sb = r_strbuf_new ("");
	while (start < end) {
		r_strbuf_appendf (sb, "%02x ", *start);
		start++;
	}
	r_strbuf_append (sb, "\n");
	return r_strbuf_drain (sb);
}

static char *decode_buffer(PJ *pj, const ut8* start, const ut8* end, int padcnt, int mode) {
	RStrBuf *sb = r_strbuf_new ("");
	size_t bytes_read = 0;
	ut32 var32 = 0;
	ut64 var64 = 0;
	bool havepj = pj != NULL;
	if (!pj) {
		if (mode == 'J') {
			pj = pj_new ();
			pj_o (pj);
			pj_ks (pj, "type", "array");
			pj_ka (pj, "values");
		} else if (mode == 'j') {
			pj = pj_new ();
			pj_o (pj);
			pj_ka (pj, "protobuf");
		}
	}
	const ut8* buffer = start;
	while (buffer >= start && buffer < end) {
		if (!*buffer) {
			goto leave;
		}
		//ut8 byte = *buffer;
		ut8 number = buffer[0] >> 3;
		ut8 wire = buffer[0] & 0x3;
		buffer++;
		if (buffer < start || buffer >= end) {
			R_LOG_WARN ("invalid buffer pointer");
			break;
		} else if (wire > WIRE_32_BIT) {
			R_LOG_WARN ("unknown wire id (%u)", wire);
			goto leave;
		}
		if (wire != WIRE_END_GRP) {
			switch (mode) {
			case 'j':
			case 'J':
		//		pj_i (pj, number);
				break;
			case 'v':
				pad (sb, padcnt);
				r_strbuf_appendf (sb, "%u %-13s", number, s_wire (wire));
				break;
			default:
				pad (sb, padcnt);
				r_strbuf_appendf (sb, "%u", number);
				break;
			}
		}
		switch (wire) {
		case WIRE_VARINT:
			{
				st64* i = (st64*) &var64;
				bytes_read = read_u64_leb128 (buffer, end, &var64);
				if (mode == 'J') {
					pj_o (pj);
					pj_ks (pj, "type", "varint");
					pj_kn (pj, "value", *i);
					pj_end (pj);
				} else if (mode == 'j') {
					pj_n (pj, *i);
				} else {
					r_strbuf_appendf (sb, ": %"PFMT64u" | %"PFMT64d"\n", var64, *i);
				}
			}
			break;
		case WIRE_64_BIT:
			{
				ft64* f = (ft64*) &var64;
				st64* i = (st64*) &var64;
				bytes_read = read_u64_leb128 (buffer, end, &var64);
				if (mode == 'J') {
					pj_o (pj);
					pj_ks (pj, "type", "64bit");
					pj_kn (pj, "value", *i);
					double d = *f;
					pj_kd (pj, "fvalue", d);
					pj_end (pj);
				} else if (mode == 'j') {
					pj_n (pj, *i);
				} else {
					r_strbuf_appendf (sb, ": %"PFMT64u" | %"PFMT64d" | %f\n", var64, *i, *f);
				}
			}
			break;
		case WIRE_LEN_DELIM:
			{
				bytes_read = read_u64_leb128 (buffer, end, &var64);
				const ut8* ps = buffer + bytes_read;
				if ((int)var64 < 0) {
					R_LOG_ERROR ("Invalid delta in var64");
					goto leave;
				}
				if (UT64_ADD_OVFCHK ((size_t)ps, var64)) {
					R_LOG_ERROR ("Invalid overflow in var64");
					goto leave;
				}
				const ut8* pe = (const ut8*)ps + var64;
				if (ps > buffer && pe <= end) {
					if (is_string (ps, pe)) {
						if (mode == 'J') {
							pj_o (pj);
							pj_ks (pj, "type", "len-delim");
							char *ss = r_str_ndup ((const char *)ps, var64);
							pj_ks (pj, "value", ss);
							free (ss);
							pj_end (pj);
						} else if (mode == 'j') {
							char *ss = r_str_ndup ((const char *)ps, var64);
							pj_s (pj, ss);
							free (ss);
						} else {
							r_strbuf_appendf (sb, ": \"%.*s\"\n", (int)var64, (const char*) ps);
						}
					} else {
						if (mode == 'J') {
							pj_o (pj);
							pj_ks (pj, "type", "array");
							pj_ka (pj, "values");
						} else if (mode == 'j') {
							pj_a (pj);
						} else {
							r_strbuf_append (sb, " {\n");
						}
						char *child = decode_buffer (pj, ps, pe, padcnt + 1, mode);
						if (mode == 'j' || mode == 'J') {
							pj_end (pj);
							pj_end (pj);
						} else {
							r_strbuf_append (sb, child);
							pad (sb, padcnt);
							r_strbuf_append (sb, "}\n");
						}
						free (child);
					}
					bytes_read += var64;
				} else {
					R_LOG_WARN ("invalid delimited length (%"PFMT64u")", var64);
					goto leave;
				}
			}
			break;
		case WIRE_START_GRP:
			if (mode == 'j' || mode == 'J') {
				pj_o (pj);
			} else {
				r_strbuf_append (sb, "{\n");
			}
			padcnt++;
			break;
		case WIRE_END_GRP:
			if (padcnt > 1) {
				padcnt--;
			}
			if (mode == 'j' || mode == 'J') {
				pj_end (pj);
			} else {
				pad (sb, padcnt);
				r_strbuf_append (sb, "}\n");
			}
			break;
		case WIRE_32_BIT:
			{
				ft32* f = (ft32*) &var32;
				st32* i = (st32*) &var32;
				bytes_read = read_u32_leb128 (buffer, end, &var32);
				if (mode == 'J') {
					pj_o (pj);
					pj_ks (pj, "type", "32bit");
					pj_kn (pj, "value", *i);
					pj_kd (pj, "fvalue", *f);
					pj_end (pj);
				} else if (mode == 'j') {
					pj_n (pj, *i);
				} else {
					r_strbuf_appendf (sb, ": %u | %d | %f\n", var32, *i, *f);
				}
			}
			break;
		default:
			if (mode == 'J') {
				pj_o (pj);
				pj_ks (pj, "type", "array");
				char *v = decode_array (buffer - 1, end);
				pj_ks (pj, "value", v);
				free (v);
				pj_end (pj);
				pj_end (pj);
			} else if (mode == 'j') {
				char *v = decode_array (buffer - 1, end);
				pj_s (pj, v);
			} else {
				char *s = decode_array (buffer - 1, end);
				r_strbuf_appendf (sb, "%s", s);
			}
			goto leave;
		}
		buffer += bytes_read;
	}
leave:
	if (pj) {
		pj_end (pj);
		pj_end (pj);
		if (havepj) {
			r_strbuf_free (sb);
			return NULL;
		}
		char *pjs = pj_drain (pj);
		r_strbuf_appendf (sb, "%s\n", pjs);
		free (pjs);
		pj = NULL;
	}
	return r_strbuf_drain (sb);
}

R_API char *r_protobuf_decode(const ut8* start, const ut64 size, int mode) {
	if (!start || !size) {
		R_LOG_ERROR ("Invalid buffer pointer or size");
		return NULL;
	}
	const ut8* end = start + size;
	return decode_buffer (NULL, start, end, 0u, mode);
}
