/* radare - LGPL - Copyright 2009-2010 */
/* nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_core.h>
#include <r_asm.h>

R_API RCoreAsmHit *r_core_asm_hit_new() {
	RCoreAsmHit *hit = R_NEW (RCoreAsmHit);
	if (hit) {
		hit->code = NULL;
		hit->addr = -1;
	}
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
R_API RList *r_core_asm_strsearch(RCore *core, const char *input, ut64 from, ut64 to) {
	RCoreAsmHit *hit;
	RAsmAop aop;
	RList *hits;
	ut64 at, toff = core->offset;
	ut8 *buf;
	char *tok, *tokens[1024], *code = NULL, *ptr;
	int idx, tidx, ret, len; 
	int tokcount, matchcount;

	if (!(ptr = strdup (input)))
		return NULL;
	if (!(hits = r_core_asm_hit_list_new ()))
		return NULL;
	for (tokcount=0;;tokcount++) {
		if (tokcount==0) tok = (char*)strtok (ptr, ";");
		else tok = (char*)strtok (NULL, ";");
		if (tok == NULL)
			break;
		tokens[tokcount] = r_str_trim_head_tail (tok);
	}
	if (core->blocksize<=OPSZ) {
		eprintf ("error: block size too small\n");
		return R_FALSE;
	}
	buf = (ut8 *)malloc (core->blocksize);
	for (at = from, matchcount = 0; at < to; at += core->blocksize-OPSZ) {
		if (r_cons_singleton ()->breaked)
			break;
		ret = r_io_read_at (core->io, at, buf, core->blocksize);
		if (ret != core->blocksize)
			break;
		idx = 0, matchcount = 0;
		while (idx<core->blocksize) {
			r_asm_set_pc (core->assembler, at+idx);
			if (!(len = r_asm_disassemble (core->assembler, &aop, buf+idx, core->blocksize-idx))) {
				if (matchcount != 0)
					idx = tidx+1;
				else idx++;
				matchcount = 0;
				continue;
			}
			if (strstr (aop.buf_asm, tokens[matchcount])) {
				code = r_str_concatf (code, "%s; ", aop.buf_asm);
				if (matchcount == tokcount-1) {
					if (tokcount == 1)
						tidx = idx;
					if (!(hit = r_core_asm_hit_new ())) {
						r_list_destroy (hits);
						return NULL;
					}
					hit->addr = at+tidx;
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
				if (matchcount != 0)
					idx = tidx+1;
				else idx++;
				R_FREE (code);
				matchcount = 0;
			}
		}
	}
	r_asm_set_pc (core->assembler, toff);
	free (buf);
	free (ptr);
	free (code);
	return hits;
}
