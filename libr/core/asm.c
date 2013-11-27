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

static RListIter * find_addr(RList *hits, ut64 addr){
    RCoreAsmHit dummy_value;
    dummy_value.addr = addr; 
    return r_list_find (hits, &dummy_value, ((RListComparator)rcoreasm_address_comparator));    
}


static int handle_forward_sweep(RCore* core, RList *hits, ut8* buf, ut64 len, ut64 current_buf_pos, ut64 current_instr_addr, ut64 end_addr){
	ut64 temp_instr_len = 0,
		temp_instr_addr = current_instr_addr,
		tmp_current_buf_pos = current_buf_pos;
    RAsmOp op;
	RCoreAsmHit *hit = NULL;
    
    r_asm_set_pc (core->assembler, current_instr_addr);
	while ( tmp_current_buf_pos < len && temp_instr_addr != end_addr) {
		temp_instr_len = len - tmp_current_buf_pos;
		r_cons_printf("Current position: %d instr_addr: 0x%llx \n", tmp_current_buf_pos, temp_instr_addr);
		temp_instr_len = r_asm_disassemble (core->assembler, &op, buf+tmp_current_buf_pos, temp_instr_len);
		
        if (temp_instr_len == 0) 
			temp_instr_len = 1;
			 
        hit = r_core_asm_hit_new ();
		hit->addr = temp_instr_addr;
		hit->len = temp_instr_len;
		hit->code = NULL;
		r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
		
        temp_instr_addr += temp_instr_len;
        tmp_current_buf_pos += temp_instr_len;
 
	}
	return temp_instr_addr;
}


static int handle_disassembly_overlap(RCore* core, RList *hits, ut8* buf, ut64 len, ut64 current_buf_pos, ut64 current_instr_addr ) {
	RCoreAsmHit dummy_value;
	RListIter *stop_hit_iter = NULL;
    RAsmOp op;
    
	ut64 temp_instr_len = 0,
		temp_instr_addr = current_instr_addr,
		tmp_current_buf_pos = current_buf_pos,
        next_buf_pos = current_buf_pos,
        tmp_end_addr = current_instr_addr + ( len - current_buf_pos - 1);

    /* Sub optimal method (e.g. easy) */
    r_list_purge(hits);
    tmp_current_buf_pos = current_buf_pos;
    handle_forward_sweep(core, hits, buf, len, current_buf_pos, current_instr_addr, tmp_end_addr );
    next_buf_pos = current_buf_pos;
    
    /* Optimal way (Needs more work than I want to put in right now)
	// 1) forward sweep to determine if this is the best fit
	// set of instructions
	r_asm_set_pc (core->assembler, current_instr_addr);
	while (tmp_current_buf_pos < len) {
		
		RListIter * found_addr = find_addr(hits, temp_instr_addr);
        temp_instr_len = len - tmp_current_buf_pos;
        temp_instr_len = r_asm_disassemble (core->assembler, &op, buf+tmp_current_buf_pos-1, temp_instr_len);
		temp_instr_addr += temp_instr_len;
		
		// an optimization is to see if there is a hit
		// and that hit is not an invalid operation
		dummy_value.addr = temp_instr_addr; 
		stop_hit_iter = find_addr(hits, temp_instr_addr);
		
        if (stop_hit_iter) break;
		if (temp_instr_len == 0) temp_instr_len += 1;
		
        tmp_current_buf_pos += temp_instr_len;
	}

	// 2) now we need to prune hits up to stop_hit_iter
	// otherwise if stop_hit_iter == NULL we free all the hits upto addr
	if (stop_hit_iter) {
		RListIter *iter = NULL, *t_iter;
		RCoreAsmHit *del_hit = NULL;
        ut64 d_start_addr = ((RCoreAsmHit *)stop_hit_iter->data)->addr,
             d_end_addr = d_start_addr + ((RCoreAsmHit *)stop_hit_iter->data)->len;

        ut64 handle_overflow_case = d_start_addr > d_end_addr;

		r_list_foreach_safe (hits, iter, t_iter, del_hit){
			// the list is sorted by assending address 
			if ( del_hit == stop_hit_iter->data) break;
            if ( handle_overflow_case ) {

            } else {
                
            }
			if (del_hit) r_list_delete (hits, iter);
		}

	} else if (current_instr_addr == temp_instr_addr) {
		r_list_purge (hits);
	}

	// 3) forward sweep again if we hit addr
	if (temp_instr_addr == current_instr_addr || stop_hit_iter) {
        ut64 tmp_end_addr = stop_hit_iter ? ((RCoreAsmHit *)stop_hit_iter->data)->addr : current_instr_addr;
        tmp_current_buf_pos = current_buf_pos;
        handle_forward_sweep(core, hits, buf, len, current_buf_pos, current_instr_addr, tmp_end_addr );

		next_buf_pos = current_buf_pos;
		// Disasm overlap end
		
	}*/
    return next_buf_pos;
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


static RList * r_core_asm_back_sweep_disassemble_all(RCore *core, ut64 addr, ut64 len, ut64 max_hit_count, ut32 extra_padding){
    RList *hits = r_core_asm_hit_list_new ();
    RCoreAsmHit dummy_value;
    RCoreAsmHit *hit = NULL;
    RAsmOp op;
    ut8 *buf = (ut8 *)malloc (len + extra_padding);
    ut64 current_instr_len = 0, 
         current_instr_addr = addr, 
         current_buf_pos = len - 1,
         hit_count = 0;

    memset (&dummy_value, 0, sizeof (RCoreAsmHit));
    
    if (hits == NULL || buf == NULL ){
        if (hits) r_list_destroy (hits);
        if (buf) free (buf); 
        return NULL;
    }

    // added twenty for a little buffer so we can disassemble the initial addr correctly
    if (r_io_read_at (core->io, addr-(len+extra_padding), buf, len+extra_padding) != len+extra_padding) {
        r_list_destroy (hits);
        free (buf);
        return NULL;            
    }
    
    if (len == 0){
        return hits;
    }

    current_buf_pos = len - 1;
    
    do {
        
        if (r_cons_singleton ()->breaked) break;

        // reset assembler
        r_asm_set_pc (core->assembler, current_instr_addr);

        current_instr_len = len - current_buf_pos + extra_padding ;
        
        //eprintf("current_buf_pos: 0x%llx, current_instr_len: %d\n", current_buf_pos, current_instr_len);
        
        current_instr_len = r_asm_disassemble (core->assembler, &op, buf+current_buf_pos, current_instr_len);
        hit = r_core_asm_hit_new ();
        hit->addr = current_instr_addr;
        hit->len = current_instr_len;
        hit->code = NULL;
        r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
        
        current_buf_pos--;
        current_instr_addr--;
        hit_count++;

    } while ( ((int) current_buf_pos  >= 0) && (int)(len - current_buf_pos) >= 0 && hit_count <= max_hit_count);

    if (buf) free(buf);
    return hits;

}




static RList *r_core_asm_back_sweep_disassemble (RCore *core, ut64 addr, int len, ut64 max_hit_count, ut8 disassmble_each_addr, ut32 extra_padding) {
	RList *hits;;
	RCoreAsmHit *hit = NULL;
	RAsmOp op;
	ut8 *buf = NULL;



	ut64 current_instr_addr = addr-1,
		current_instr_len = 0,
		current_buf_pos = 0,
		next_buf_pos = len,
		end_addr = addr-1 - len;

	RCoreAsmHit dummy_value;

	ut32 hit_count = 0; 


    if (disassmble_each_addr){
        return r_core_asm_back_sweep_disassemble_all(core, addr, len, max_hit_count, extra_padding);
    }

    hits = r_core_asm_hit_list_new ();
    buf = malloc (len + extra_padding);

	if (hits == NULL || buf == NULL ){
		if (hits) r_list_destroy (hits);
		if (buf) free (buf); 
		return NULL;
	}

	// added twenty for a little buffer so we can disassemble the initial addr correctly
	if (r_io_read_at (core->io, addr-(len+extra_padding), buf, len+extra_padding) != len+extra_padding) {
		r_list_destroy (hits);
		free (buf);
		return NULL;			
	}

	//
	// XXX - This is a heavy handed approach without a 
	// 		an appropriate btree or hash table for storing
	//	 hits, because are using:
	//			1) Sorted RList with many inserts and searches
	//			2) Pruning hits to find the most optimal
	//				disassembly with backward + forward sweep

	// greedy approach 
	// 1) Consume previous bytes
	// 1a) Instruction is invalid (incr current_instr_addr)
	// 1b) Disasm is perfect 
	// 1c) Disasm is underlap (disasm(current_instr_addr, next_instr_addr - current_instr_addr) short some bytes) 
	// 1d) Disasm is overlap (disasm(current_instr_addr, next_instr_addr - current_instr_addr) over some bytes)

	memset (&dummy_value, 0, sizeof (RCoreAsmHit));
	current_buf_pos = len - 1;
    next_buf_pos = len - 1 + extra_padding;
	do {
		
		if (r_cons_singleton ()->breaked) break;

        RListIter *found_addr = find_addr(hits, current_instr_addr);
		// reset assembler
		r_asm_set_pc (core->assembler, current_instr_addr);

		current_instr_len = next_buf_pos - current_buf_pos;
		
		//eprintf("current_buf_pos: 0x%llx, current_instr_len: %d\n", current_buf_pos, current_instr_len);
		
		current_instr_len = r_asm_disassemble (core->assembler, &op, buf+current_buf_pos, current_instr_len);
		
		
		if (current_instr_len == 0 || strstr (op.buf_asm, "invalid")) {
			if (current_instr_len == 0) current_instr_len = 1;

			hit = r_core_asm_hit_new ();
			hit->addr = current_instr_addr;
			hit->len = current_instr_len;
			hit->code = NULL;
			r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
			//next_buf_pos = current_buf_pos;
            hit_count++;
        } else if (current_buf_pos + current_instr_len == next_buf_pos) {
			// Disasm perfect
			hit = r_core_asm_hit_new ();
			hit->addr = current_instr_addr;
			hit->len = current_instr_len;
			hit->code = NULL;
			r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
            hit_count ++;	
			next_buf_pos = current_buf_pos;

		} else if (current_buf_pos + current_instr_len < next_buf_pos) {
			// Disasm underlap
			// Simplicity consume the instruction, and 
			// fill the next hits with a forward sweep
			ut64 temp_instr_addr = handle_forward_sweep(core, hits, buf, len, current_buf_pos, current_instr_addr, end_addr);
            next_buf_pos = current_buf_pos;
            hit_count = r_list_length(hits);

			// Disasm underlap end
		} else if (current_buf_pos + current_instr_len > next_buf_pos) {
			// Disasm overlap
			// forward sweep to see if we find a perfect match,
			// if so we remove all hits up to the perfect match
			// and we reset all the hits
			ut64 value = handle_disassembly_overlap(core, hits, buf, len, current_buf_pos, current_instr_addr);
            next_buf_pos = current_buf_pos;
            hit_count = r_list_length(hits);
        }

		// walk backwards by one instruction
		current_instr_addr -= 1;
		current_buf_pos -= 1;
        
		//eprintf(" addr: 0x%04llx end_addr: 0x%04llx len: %d\n" , addr, end_addr, len);
		//eprintf(" current_instr_addr: %d current_instr_len: %d next_instr_addr: 0x%04llx \n", current_instr_addr, current_instr_len, next_instr_addr );
	} while ( ((int) current_buf_pos  >= 0) && (len - current_buf_pos) >= 0 && hit_count <= max_hit_count);

	r_asm_set_pc (core->assembler, addr);
	if (buf) free (buf);
	return hits;
}

R_API RList *r_core_asm_back_sweep_disassemble_instr (RCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding){
	// extra padding to allow for additional disassembly on border buffer cases
    ut8 disassmble_each_addr  = R_FALSE;
	return r_core_asm_back_sweep_disassemble(core, addr, len, hit_count, disassmble_each_addr, extra_padding);
}

R_API RList *r_core_asm_back_sweep_disassemble_byte (RCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding){
	ut8 disassmble_each_addr  = R_TRUE;
    // extra padding to allow for additional disassembly on border buffer cases
	return r_core_asm_back_sweep_disassemble(core, addr, len, hit_count, disassmble_each_addr, extra_padding);
}
