static void gdiff_copy(ut64 from, ut64 to) {
	while (from < to) {
		const ut32 len = R_MIN (to - from, ST32_MAX);
		ut8 record[13];
		size_t size;
		if (from > ST32_MAX) {
			record[0] = 255;
			r_write_be64 (record + 1, from);
			r_write_be32 (record + 9, len);
			size = 13;
		} else {
			if (from <= UT16_MAX) {
				record[0] = 249;
				r_write_be16 (record + 1, from);
				size = 3;
			} else {
				record[0] = 252;
				r_write_be32 (record + 1, from);
				size = 5;
			}
			if (len <= UT8_MAX) {
				record[size++] = len;
			} else if (len <= UT16_MAX) {
				record[0]++;
				r_write_be16 (record + size, len);
				size += 2;
			} else {
				record[0] += 2;
				r_write_be32 (record + size, len);
				size += 4;
			}
		}
		print_bytes (record, size, false);
		from += len;
	}
}
