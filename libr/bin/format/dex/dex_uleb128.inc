// XXX we should use r_util apis only

#define LEB_MAX_SIZE 6
int dex_uleb128_len(const ut8 *ptr, int size) {
	int i = 1, result = *(ptr++);
	while (result > 0x7f && i <= LEB_MAX_SIZE && i < size) {
		result = *(ptr++);
		i++;
	}
	return i;
}

#define SIG_EXTEND(X,Y) X = ((X) << (Y)) >> Y
int dex_read_sleb128(const char *ptr, int size) {
	int cur, result;
	ut8 len = dex_uleb128_len ((const ut8*)ptr, size);
	if (len > size) {
		return 0;
	}
	ptr += len - 1;
	result = *(ptr--);

	if (result <= 0x7f) {
		SIG_EXTEND (result, 25);
	} else {
		cur = *(ptr--);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur <= 0x7f) {
			SIG_EXTEND (result, 18);
		} else {
			cur = *(ptr--);
			result |= (cur & 0x7f) << 14;
			if (cur <= 0x7f) {
				SIG_EXTEND (result, 11);
			} else {
				cur = *(ptr--);
				result |= (cur & 0x7f) << 21;
				if (cur <= 0x7f) {
					SIG_EXTEND (result, 4);
				} else {
					cur = *(ptr--);
					result |= cur << 28;
				}
			}
		}
	}
	return result;
}

