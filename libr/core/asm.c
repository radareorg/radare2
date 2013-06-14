/* radare - LGPL - Copyright 2009-2012 - nibble */

#include <r_types.h>
#include <r_core.h>
#include <r_asm.h>

R_API RCoreAsmHit *r_core_asm_hit_new() {
	RCoreAsmHit *hit = R_NEW (RCoreAsmHit);
	if (!hit) return NULL;
	hit->code = NULL;
	hit->len = 0;
	hit->addr = -1;
	return hit;
}

R_API RList *r_core_asm_hit_list_new() {
	RList *list = r_list_new ();
	list->free = &r_core_asm_hit_free;
	return list;
}

R_API void r_core_asm_hit_free(void *_hit) {
	RCoreAsmHit *hit = _hit;
	if (hit) {
		if (hit->code)
			free (hit->code);
		free (hit);
	}
}

R_API char* r_core_asm_search(RCore *core, const char *input, ut64 from, ut64 to) {
	RAsmCode *acode;
	char *ret;
	if (!(acode = r_asm_massemble (core->assembler, input)))
		return NULL;
	ret = strdup (acode->buf_hex);
	r_asm_code_free (acode);
	return ret;
}

#define OPSZ 8
// TODO: add support for byte-per-byte opcode search
R_API RList *r_core_asm_strsearch(RCore *core, const char *input, ut64 from, ut64 to) {
	RCoreAsmHit *hit;
	RAsmOp op;
	RList *hits;
	ut64 at, toff = core->offset;
	ut8 *buf;
	char *tok, *tokens[1024], *code = NULL, *ptr;
	int idx, tidx = 0, ret, len;
	int tokcount, matchcount;

	if (!*input)
		return NULL;
	if (core->blocksize<=OPSZ) {
		eprintf ("error: block size too small\n");
		return NULL;
	}
	if (!(buf = (ut8 *)malloc (core->blocksize)))
		return NULL;
	if (!(ptr = strdup (input))) {
		free (buf);
		return NULL;
	}
	if (!(hits = r_core_asm_hit_list_new ())) {
		free (buf);
		free (ptr);
		return NULL;
	}
	tokens[0] = NULL;
	for (tokcount=0; tokcount<sizeof (tokens); tokcount++) {
		tok = strtok (tokcount? NULL: ptr, ",");
		if (tok == NULL)
			break;
		tokens[tokcount] = r_str_trim_head_tail (tok);
	}
	tokens[tokcount] = NULL;
	r_cons_break (NULL, NULL);
	for (at = from, matchcount = 0; at < to; at += core->blocksize-OPSZ) {
		if (r_cons_singleton ()->breaked)
			break;
		ret = r_io_read_at (core->io, at, buf, core->blocksize);
		if (ret != core->blocksize)
			break;
		idx = 0, matchcount = 0;
		while (idx<core->blocksize) {
			r_asm_set_pc (core->assembler, at+idx);
			op.buf_asm[0] = 0;
			op.buf_hex[0] = 0;
			if (!(len = r_asm_disassemble (core->assembler, &op, buf+idx, core->blocksize-idx))) {
				idx = (matchcount)? tidx+1: idx+1;
				matchcount = 0;
				continue;
			}
			if (tokens[matchcount] && strstr (op.buf_asm, tokens[matchcount])) {
				code = r_str_concatf (code, "%s", op.buf_asm);
				if (matchcount == tokcount-1) {
					if (tokcount == 1)
						tidx = idx;
					if (!(hit = r_core_asm_hit_new ())) {
						r_list_destroy (hits);
						hits = NULL;
						goto beach;
					}
					hit->addr = at+tidx;
					hit->len = idx+len-tidx;
					if (hit->len == -1) {
						r_core_asm_hit_free (hit);
						goto beach;
					}
					hit->code = strdup (code);
					r_list_append (hits, hit);
					R_FREE (code);
					matchcount = 0;
					idx = tidx+1;
				} else  if (matchcount == 0) {
					tidx = idx;
					matchcount++;
					idx += len;
				} else {
					matchcount++;
					idx += len;
				}
			} else {
				idx = matchcount? tidx+1: idx+1;
				R_FREE (code);
				matchcount = 0;
			}
		}
	}
	r_asm_set_pc (core->assembler, toff);
beach:
	free (buf);
	free (ptr);
	free (code);
	return hits;
}

R_API RList *r_core_asm_bwdisassemble (RCore *core, ut64 addr, int n, int len) {
	RCoreAsmHit *hit;
	RAsmOp op;
	RList *hits = NULL;
	ut8 *buf;
	ut64 at;
	int instrlen, ni, idx;

	if (!(hits = r_core_asm_hit_list_new ()))
		return NULL;
	buf = (ut8 *)malloc (len);
	if (!buf) {
		r_list_destroy (hits);
		return NULL;
	}
	if (r_io_read_at (core->io, addr-len, buf, len) != len) {
		r_list_destroy (hits);
		free (buf);
		return NULL;
	}
	for (idx = 1; idx < len; idx++) {
		if (r_cons_singleton ()->breaked)
			break;
		at = addr - idx; ni = 1;
		while (at < addr) {
			r_asm_set_pc (core->assembler, at);
			//XXX HACK We need another way to detect invalid disasm!!
			if (!(instrlen = r_asm_disassemble (core->assembler, &op, buf+(len-(addr-at)), addr-at)) || strstr (op.buf_asm, "invalid")) {
				break;
			} else {
				at += instrlen;
				if (at == addr) {
					if (ni == n) {
						if (!(hit = r_core_asm_hit_new ())) {
							r_list_destroy (hits);
							free (buf);
							return NULL;
						}
						hit->addr = addr-idx;
						hit->len = idx;
						hit->code = NULL;
						r_list_append (hits, hit);
					}
				} else ni++;
			}
		}
	}
	r_asm_set_pc (core->assembler, addr);
	free (buf);
	return hits;
}
