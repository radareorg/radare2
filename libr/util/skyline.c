/* radare2 - LGPL - Copyright 2020 - GustavoLCR */

#include <r_skyline.h>

#define CMP_BEGIN_GTE_PART(addr, part) \
	(((addr) > (r_itv_begin (((RSkylineItem *)(part))->itv))) - ((addr) < (r_itv_begin (((RSkylineItem *)(part))->itv))))

#define CMP_END_GTE_PART(addr, part) \
	(((addr) < (r_itv_end (((RSkylineItem *)(part))->itv)) || !r_itv_end (((RSkylineItem *)(part))->itv)) ? -1 : 1)

R_API bool r_skyline_add(RSkyline *skyline, RInterval itv, void *user) {
	r_return_val_if_fail (skyline && r_itv_size (itv), false);
	RVector *skyline_vec = &skyline->v;
	RSkylineItem new_part = { itv, user };
	const ut64 new_part_end = r_itv_end (new_part.itv);

	// `slot` is the index of the first RSkylineItem with part->itv.addr >= new_part.itv.addr
	size_t slot;
	r_vector_lower_bound (skyline_vec, new_part.itv.addr, slot, CMP_BEGIN_GTE_PART);
	const bool is_last = slot == r_vector_len (skyline_vec);
	bool is_inside_prev_part = false;
	if (slot) {
		RSkylineItem *prev_part = r_vector_index_ptr (skyline_vec, slot - 1);
		const ut64 prev_part_end = r_itv_end (prev_part->itv);
		if (prev_part_end > r_itv_begin (new_part.itv)) {
			prev_part->itv.size = r_itv_begin (new_part.itv) - r_itv_begin (prev_part->itv);
			if (prev_part_end > new_part_end) {
				RSkylineItem tail;
				tail.user = prev_part->user;
				tail.itv.addr = new_part_end;
				tail.itv.size = prev_part_end - r_itv_begin (tail.itv);
				r_vector_insert (skyline_vec, slot, &tail);
				is_inside_prev_part = true;
			}
		}
	}
	if (!is_last && !is_inside_prev_part) {
		RSkylineItem *part = r_vector_index_ptr (skyline_vec, slot);
		while (part && r_itv_include (new_part.itv, part->itv)) {
			// Remove `part` that fits in `new_part`
			r_vector_remove_at (skyline_vec, slot, NULL);
			part = slot < r_vector_len (skyline_vec) ? r_vector_index_ptr (skyline_vec, slot) : NULL;
		}
		if (part && r_itv_overlap (new_part.itv, part->itv)) {
			// Chop start of last `part` that intersects `new_part`
			const ut64 oaddr = r_itv_begin (part->itv);
			part->itv.addr = new_part_end;
			part->itv.size -= r_itv_begin (part->itv) - oaddr;
		}
	}
	r_vector_insert (skyline_vec, slot, &new_part);
	return true;
}

R_API const RSkylineItem *r_skyline_get_item_intersect(RSkyline *skyline, ut64 addr, ut64 len) {
	r_return_val_if_fail (skyline, NULL);
	RVector *skyline_vec = &skyline->v;
	size_t i, l = r_vector_len (skyline_vec);
	r_vector_lower_bound (skyline_vec, addr, i, CMP_END_GTE_PART);
	if (i == l) {
		return false;
	}
	const RSkylineItem *item = r_vector_index_ptr (skyline_vec, i);
	return item->itv.addr <= addr + len ? item : NULL;
}
