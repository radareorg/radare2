/* radare - LGPL - Copyright 2009-2012 - nibble */

#include <r_types.h>
#include <r_core.h>
#include <r_asm.h>

static int rcoreasm_address_comparator(RCoreAsmHit *a, RCoreAsmHit *b){
	if (a->addr == b->addr)
		return 0;
	else if (a->addr < b->addr)
		return -1;
	// a->addr > b->addr
	return 1;

}

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

	if (!(hits = r_core_asm_hit_list_new ())) return NULL;
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
		if (r_cons_singleton ()->breaked) break;
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


static RList *r_core_asm_back_sweep_disassemble (RCore *core, ut64 addr, int max_hit_count, int len, ut8 cnt_instr, ut8 ignore_invalid) {
	RList *hits = r_core_asm_hit_list_new ();
	RCoreAsmHit *hit = NULL;
	RAsmOp op;
	ut8 *buf = (ut8 *)malloc (len),
		count_instructions = cnt_instr;

	int hit_count = 0, 
		addr_offset_to_zero = len;
	
	if (hits == NULL || buf == NULL ){
		if (hits) r_list_destroy (hits);
		if (buf) free (buf); 
		return NULL;
	}
	

	// XXX - hack in some basic adjustments, which assumes the 
	// addres space will never be up in high values of 64bit space
	// e.g. if addr == 0x19 and len == 78, then the above check will not
	// so see need to fix that by letting the wrapparound happen 
	// converting it to an and then adding it back to len
	// this will give us the new buffer size (win!) 
	
	if (addr < addr - len)
		addr_offset_to_zero = len + ((int) (addr-len));

	if (r_io_read_at (core->io, addr-addr_offset_to_zero, buf, len) != len) {
		r_list_destroy (hits);
		free (buf);
		return NULL;			
	}

	{
		
		ut64 next_instr_addr = addr,
			 current_instr_addr = addr,
			 current_instr_len = 0,
			 current_buf_pos = 0;

		//
		// XXX - This is a heavy handed approach without a 
		// 		 an appropriate btree or hash table for storing
		//       hits, because are using:
		//			1) Sorted RList with many inserts and searches
		//			2) Pruning hits to find the most optimal
		//				disassembly with backward + forward sweep

		// greedy approach 
		// 1) Consume previous bytes
		// 1a) Instruction is invalid (incr current_instr_addr)
		// 1b) Disasm is perfect 
		// 1c) Disasm is underlap (disasm(current_instr_addr, next_instr_addr - current_instr_addr) short some bytes) 
		// 1d) Disasm is overlap (disasm(current_instr_addr, next_instr_addr - current_instr_addr) over some bytes)

		do {
			if (r_cons_singleton ()->breaked) break;

			// reset assembler
			r_asm_set_pc (core->assembler, current_instr_addr);

			current_buf_pos = addr - (addr - current_instr_addr);
			current_instr_len = next_instr_addr - current_instr_addr;
			current_instr_len = r_asm_disassemble (core->assembler, &op, buf+current_buf_pos, current_instr_len);

			if (current_instr_len == 0 || strstr (op.buf_asm, "invalid")) {
				if (current_instr_len == 0) current_instr_len = 1;
				if (!ignore_invalid) {
					hit = r_core_asm_hit_new ();
					hit->addr = current_instr_addr;
					hit->len = current_instr_len;
					hit->code = NULL;
					r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
					if (count_instructions) hit_count ++;
					else hit_count += current_instr_len;					
				}
			} else if (current_instr_addr + current_instr_len == next_instr_addr) {
				// Disasm perfect
				hit = r_core_asm_hit_new ();
				hit->addr = current_instr_addr;
				hit->len = current_instr_len;
				hit->code = NULL;
				r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
				next_instr_addr = current_instr_addr;
				if (count_instructions) hit_count ++;
				else hit_count += current_instr_len;

			} else if (current_instr_addr + current_instr_len < next_instr_addr) {
				// Disasm underlap
				// Simplicity consume the instruction, and 
				// fill the next hits with a forward sweep
				ut64 temp_instr_len = current_instr_len,
					 temp_instr_addr = current_instr_addr + current_instr_len;

				hit = r_core_asm_hit_new ();
				hit->addr = current_instr_addr;
				hit->len = current_instr_len;
				hit->code = NULL;
				r_list_append (hits, hit);

				// forward sweep from current location
				r_asm_set_pc (core->assembler, temp_instr_addr);
				while (temp_instr_addr < next_instr_addr) {
					
					temp_instr_len = next_instr_addr - temp_instr_addr;
					current_buf_pos = len - (addr - temp_instr_addr);
					temp_instr_len = r_asm_disassemble (core->assembler, &op, buf+current_buf_pos, temp_instr_len);
					
					if (temp_instr_len == 0 || strstr (op.buf_asm, "invalid")) {
						if (temp_instr_len == 0) 
							temp_instr_len = 1;

						if (!ignore_invalid) {
							hit = r_core_asm_hit_new ();
							hit->addr = temp_instr_addr;
							hit->len = temp_instr_len;
							hit->code = NULL;
							r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
							
							if (count_instructions) hit_count ++;
							else hit_count += temp_instr_len;					
						}
						// big difference is we do not update next instr addr here
					} else {
						hit = r_core_asm_hit_new ();
						hit->addr = temp_instr_addr;
						hit->len = temp_instr_len;
						hit->code = NULL;
						r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));

						if (count_instructions) hit_count ++;
						else hit_count += current_instr_len;

					}
					temp_instr_addr += temp_instr_len;
				}

				// done up until the current instruction
				// so update
				next_instr_addr = current_instr_addr;
				if (count_instructions) hit_count ++;
				else hit_count += current_instr_len;

				// Disasm underlap end
			} else if (current_instr_addr + current_instr_len > next_instr_addr) {
				// Disasm overlap
				// forward sweep to see if we find a perfect match,
				// if so we remove all hits up to the perfect match
				// and we reset all the hits
				RCoreAsmHit dummy_value;
				RListIter *stop_hit_iter = NULL;

				ut64 temp_instr_len = current_instr_len,
					 temp_instr_addr = current_instr_addr + current_instr_len;
				
				memset (&dummy_value, 0, sizeof (RCoreAsmHit));
				// 1) forward sweep to determine if this is the best fit
				// set of instructions
				r_asm_set_pc (core->assembler, current_instr_addr);
				while (temp_instr_addr < addr) {
					
					temp_instr_len = addr - temp_instr_addr;
					current_buf_pos = len - (addr - temp_instr_addr);
					temp_instr_len = r_asm_disassemble (core->assembler, &op, buf+current_buf_pos, temp_instr_len);
					temp_instr_addr += temp_instr_len;


					// an optimization is to see if there is a hit
					// and that hit is not an invalid operation
					dummy_value.addr = temp_instr_addr; 
					stop_hit_iter = r_list_find (hits, &dummy_value, ((RListComparator)rcoreasm_address_comparator));
					if (stop_hit_iter) {
						break;
					}
				}

				// 2) now we need to prune hits up to stop_hit_iter
				// otherwise if stop_hit_iter == NULL we free all the hits upto addr
				if (stop_hit_iter) {
					RListIter *iter = NULL, *t_iter;
					RCoreAsmHit *del_hit = NULL;
					r_list_foreach_safe (hits, iter, t_iter, del_hit){
						
						// the list is sorted by assending address 
						if ( del_hit == stop_hit_iter->data) break;
						
						if (del_hit) {
							r_list_delete (hits, iter);
						}
					}
				} else if (addr == temp_instr_addr) {
					r_list_purge (hits);
				}

				// 3) forward sweep again if we hit addr
				if (temp_instr_addr == addr || stop_hit_iter) {
					ut64 tmp_end_addr = stop_hit_iter ? ((RCoreAsmHit *)stop_hit_iter->data)->addr : addr;
					// reset the value of instr count
					hit_count = 0;

					r_asm_set_pc (core->assembler, current_instr_addr);
					while (temp_instr_addr < tmp_end_addr) {
						
						temp_instr_len = tmp_end_addr - temp_instr_addr;
						current_buf_pos = len - (addr - temp_instr_addr);
						temp_instr_len = r_asm_disassemble (core->assembler, &op, buf+current_buf_pos, temp_instr_len);
						if (temp_instr_len == 0 || strstr (op.buf_asm, "invalid")) {
							if (temp_instr_len == 0) 
								temp_instr_len = 1;

							if (!ignore_invalid) {
								hit = r_core_asm_hit_new ();
								hit->addr = temp_instr_addr;
								hit->len = temp_instr_len;
								hit->code = NULL;
								r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
								
								if (count_instructions) hit_count ++;
								else hit_count += temp_instr_len;					
							}
							// big difference is we do not update next instr addr here
						} else {
							hit = r_core_asm_hit_new ();
							hit->addr = temp_instr_addr;
							hit->len = temp_instr_len;
							hit->code = NULL;
							r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
							temp_instr_addr += temp_instr_len;

							if (count_instructions) hit_count ++;
							else hit_count += current_instr_len;

							// this expansion could change the number of hits allowed					
						}
	
						if (hit_count > max_hit_count-1) break;
					}

					if (hit_count > max_hit_count-1) break;
					
					// add the current instructoin
					hit = r_core_asm_hit_new ();
					hit->addr = current_instr_addr;
					hit->len = current_instr_len;
					hit->code = NULL;
					r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
					
					next_instr_addr = current_instr_addr;

					if (count_instructions) hit_count ++;
					else hit_count += current_instr_len;

					// Disasm overlap end
				}
			}
			current_instr_addr -= current_instr_len;

			// this is here because its
			// easier to pop out of the loop
			// without trouble
			if (hit_count > max_hit_count-1) break;
		} while ( (current_instr_addr) != (ut64)-1 );
	}

	r_asm_set_pc (core->assembler, addr);
	free (buf);
	return hits;
}

R_API RList *r_core_asm_back_sweep_disassemble_instr (RCore *core, ut64 addr, int count, int len, ut8 ignore_invalid){
	ut8 count_instructions = 1;
	return r_core_asm_back_sweep_disassemble(core, addr, count, len, count_instructions, ignore_invalid);
}

R_API RList *r_core_asm_back_sweep_disassemble_byte (RCore *core, ut64 addr, int count, int len, ut8 ignore_invalid){
	ut8 count_instructions = 0;
	return r_core_asm_back_sweep_disassemble(core, addr, count, len, count_instructions, ignore_invalid);
}
