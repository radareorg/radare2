/* radare - LGPL - Copyright 2026 - pancake */

static int gdb_reg_value(RDebug *dbg, const gdb_reg_t *wire, const char *value, char *out, size_t max_len, ut32 *synced) {
	if (!wire->size || (wire->size & 7) || wire->size > INT_MAX) {
		return -1;
	}
	const int wire_len = wire->size / 8;
	if (!value && (!out || wire_len * 2 >= max_len)) {
		return -1;
	}
	if (value && (strlen (value) != wire_len * 2 || strspn (value, "0123456789abcdefABCDEF") != wire_len * 2)) {
		return -1;
	}
	RReg *reg = dbg->reg;
	RRegItem *item = r_reg_get (reg, wire->name, R_REG_TYPE_ALL);
	ut8 *bytes = NULL;
	int ret = -1;
	if (!item || !r_reg_value_arena (reg, item)) {
		goto beach;
	}
	const int reg_len = item->size / 8;
	if (reg_len != wire_len && (reg_len > 8 || wire_len > 8)) {
		goto beach;
	}
	const ut32 mask = 1U << item->arena;
	if (!(*synced & mask) && !r_debug_reg_sync (dbg, item->arena, false)) {
		goto beach;
	}
	*synced |= mask;
	const int size = R_MAX (reg_len, wire_len);
	bytes = calloc (2, size);
	if (!bytes || !r_reg_get_value_bytes (reg, item, bytes + size, reg_len)) {
		goto beach;
	}
	const bool be = (reg->endian & R_SYS_ENDIAN_BIG) == R_SYS_ENDIAN_BIG;
	const int reg_offset = be? size - reg_len: 0;
	const int wire_offset = be? size - wire_len: 0;
	if (value) {
		if (r_hex_str2bin (value, bytes + wire_offset) != wire_len
				|| !r_reg_set_value_bytes (reg, item, bytes + reg_offset, reg_len)) {
			goto beach;
		}
		if (!r_debug_reg_sync (dbg, item->arena, true)) {
			r_reg_set_value_bytes (reg, item, bytes + size, reg_len);
			goto beach;
		}
		ret = 0;
	} else {
		memcpy (bytes + reg_offset, bytes + size, reg_len);
		r_hex_bin2str (bytes + wire_offset, wire_len, out);
		ret = wire_len * 2;
	}
beach:
	free (bytes);
	r_unref (item);
	return ret;
}

static int gdb_cmd_reg(RDebug *dbg, gdb_reg_t *registers, const char *cmd, char *out, size_t max_len) {
	if (!registers) {
		return -1;
	}
	ut32 synced = 0;
	if (*cmd) {
		const char *name = r_str_trim_head_ro (cmd);
		const char *value = strchr (name, '=');
		const size_t name_len = value? value - name: strlen (name);
		if (value) {
			value++;
			if (r_str_startswith (value, "0x")) {
				value += 2;
			}
		}
		gdb_reg_t *wire;
		for (wire = registers; *wire->name; wire++) {
			if (strlen (wire->name) == name_len && !strncmp (wire->name, name, name_len)) {
				return gdb_reg_value (dbg, wire, value, out, max_len, &synced);
			}
		}
		return -1;
	}
	if (!out || !max_len) {
		return -1;
	}
	int ret = 0;
	gdb_reg_t *wire;
	for (wire = registers; *wire->name; wire++) {
		int len = gdb_reg_value (dbg, wire, NULL, out + ret, max_len - ret, &synced);
		if (len < 0 || len > INT_MAX - ret) {
			out[0] = 0;
			return -1;
		}
		ret += len;
	}
	out[ret] = 0;
	return ret;
}
