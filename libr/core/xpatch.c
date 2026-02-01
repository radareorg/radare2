/* radare - LGPL - Copyright 2025-2026 - pancake */

#include <r_core.h>

static bool getpair(char *s, ut64 *addr, ut64 *size) {
	char *comma = strchr (s, ',');
	if (comma) {
		*comma++ = 0;
		*addr = r_num_get (NULL, s);
		*size = r_num_get (NULL, comma);
		return true;
	}
	return false;
}

static bool ishexchar(const char ch) {
	if (isdigit (ch)) {
		return true;
	}
	if (ch >= 'a' && ch <= 'f') {
		return true;
	}
	if (ch >= 'A' && ch <= 'F') {
		return true;
	}
	return false;
}

static ut8 *parse_hexpairs_line(char *line, size_t *out_len) {
	char *end_quote = strchr (line + 3, '\'');
	if (!end_quote) {
		return NULL;
	}
	*end_quote = 0;
	return r_hex_str2bin_dup (line + 3, out_len);
}

static bool verify_hexpairs(char *line, ut64 addr, const ut8 *data, size_t size) {
	size_t hex_len = 0;
	ut8 *hex_bytes = parse_hexpairs_line (line, &hex_len);
	if (!hex_bytes) {
		R_LOG_ERROR ("Failed to parse hexpairs");
		return false;
	}
	if (hex_len != size) {
		R_LOG_ERROR ("Hexpair length mismatch. Expected %d bytes, got %d", (int)size, (int)hex_len);
		free (hex_bytes);
		return false;
	}
	bool match = !memcmp (hex_bytes, data, size);
	free (hex_bytes);
	if (!match) {
		R_LOG_ERROR ("original data does not match at 0x%08"PFMT64x, addr);
	}
	return match;
}

static bool write_hexpairs(RIO *io, char *line, ut64 addr, size_t size) {
	size_t hex_len = 0;
	ut8 *hex_bytes = parse_hexpairs_line (line, &hex_len);
	if (!hex_bytes) {
		R_LOG_ERROR ("Failed to parse hexpairs");
		return false;
	}
	if (hex_len != size) {
		R_LOG_ERROR ("Hexpair length mismatch. Expected %d bytes, got %d", (int)size, (int)hex_len);
		free (hex_bytes);
		return false;
	}
	r_io_write_at (io, addr, hex_bytes, hex_len);
	free (hex_bytes);
	return true;
}

// unified binary patch
typedef struct {
	ut64 add_addr;
	ut64 add_size;
	ut64 sub_addr;
	ut64 sub_size;
	char type[8];
	bool add;
} UBP_Block;

typedef struct {
	ut8 *data;
	size_t size;
	bool be;
} UBP_Entry;

typedef struct {
	char *file;
	char *tstamp;
	bool add;
} UBP_File;

typedef struct {
	bool happens;
	const char *msg;
} UBP_Error;

static bool ubp_parseFile(const char *line, UBP_File *uf, bool add) {
	uf->add = add;
	char *tab = strchr (line, '\t');
	if (tab) {
		size_t tab_pos = tab - line;
		uf->file = r_str_ndup (line, tab_pos);
		r_str_trim (uf->file);
		uf->tstamp = r_str_trim_dup (tab + 1);
	} else {
		uf->file = r_str_trim_dup (line);
		uf->tstamp = NULL;
	}
	return true;
}

static bool ubp_parseBlock(char *line, UBP_Block *b) {
	// @@ -0x00189ca8,4 +0x00189ca8,4 @@
	// @@ -1612969,char[3] +1612969,char[3] @@
	// @@ -0x00189ca8,char[4] +0x00189ca8,char[4] @@
	// @@ -0x00189ca8,uint32_t[3] +0x00189ca8,uint32_t[3] @@
	// @@ -0x00189ca8,12 +0x00189ca8,12 @@
	// Initialize members to ensure they're not left uninitialized
	b->add_addr = 0;
	b->add_size = 0;
	b->sub_addr = 0;
	b->sub_size = 0;
	char *plus = strchr (line, '+');
	if (!plus) {
		R_LOG_ERROR ("Invalid patch format, Cant find +");
		return false;
	}
	// Extract the part after "+" which contains the add address and size
	if (!getpair (plus + 1, &b->add_addr, &b->add_size)) {
		R_LOG_ERROR ("Invalid patch format, Cant find comma in add part of @@ line");
		return false;
	}
	// Extract the part after "-" which contains the sub address and size
	char *minus = strchr (line, '-');
	if (!minus) {
		R_LOG_ERROR ("Invalid patch format, Cant find - in @@ line");
		return false;
	}
	if (!getpair (minus + 1, &b->sub_addr, &b->sub_size)) {
		R_LOG_ERROR ("Invalid patch format, Cant find comma in sub part of @@ line");
		return false;
	}
	if (b->add_size != b->sub_size) {
		// unmatching stuff
	}
	return true;
}

R_API bool r_core_patch_unified(RCore *core, const char *patch, int level, bool revert) {
	R_RETURN_VAL_IF_FAIL (core && patch, false);
	bool res = true;
	RIODesc *desc = NULL;
	UBP_File ubpFileAdd = {0};
	UBP_File ubpFileDel = {0};
	UBP_Block ubpBlock = {0};
#if 0
	UBP_Entry ubpAdd;
	UBP_Entry ubpDel;
// 	UBP_Error error;
#endif
	char *line = NULL;
	const char *p = patch;
	while (res) {
		const char *nl = strchr (p, '\n');
		if (!nl) {
			break;
		}
		line = r_str_ndup (p, nl - p);
		if (r_str_startswith (line, "--- ")) {
			if (!ubp_parseFile (line + 4, &ubpFileDel, false)) {
				res = false;
			}
			if (desc) {
				r_io_desc_free (desc);
				desc = NULL;
			}
		} else if (r_str_startswith (line, "+++ ")) {
			if (!ubp_parseFile (line + 4, &ubpFileAdd, true)) {
				res = false;
			} else {
				if (desc) {
					R_LOG_WARN ("Invalid patch format, cannot open file twice");
				}
				if (level) {
					R_LOG_TODO ("patch level not implemented yet");
				}
				desc = r_core_file_open (core, ubpFileAdd.file, R_PERM_RW, 0);
				if (!desc) {
					R_LOG_ERROR ("Cannot open %s", ubpFileAdd.file);
					res = false;
				} else {
					ut64 size = r_io_desc_size (desc);
					r_io_map_add (core->io, desc->fd, R_PERM_RW, 0, 0, size);
				}
			}
		} else if (r_str_startswith (line, "@@ ")) {
			if (!ubp_parseBlock (line, &ubpBlock)) {
				R_LOG_ERROR ("Invalid patch format, Cant find +");
				res = false;
			}
		} else if (r_str_startswith (line, "- ")) {
			// - LE 0x001b7358 # 1799000 comment after the # symbol, could be assembly
			if (revert) {
				R_LOG_TODO ("Revert mode not yet implemented");
			} else {
				// ensure the bytes removed are there otherwise fail
				ut64 addr = ubpBlock.sub_addr;
				ut64 size = ubpBlock.sub_size;
				ut8 *data = calloc (size, 1);
				if (!data) {
					R_LOG_ERROR ("Cannot allocate %d bytes", (int)size);
					res = false;
				} else {
					r_io_read_at (core->io, addr, data, size);
					if (r_str_startswith (line + 2, "LE ")) {
						if (size == 4) {
							ut8 buf[4] = {0};
							ut32 n = r_num_get (NULL, line + 2 + 3);
							r_write_le32 (buf, n);
							if (memcmp (buf, data, size)) {
								R_LOG_ERROR ("original data does not match. Expected %d found %d at 0x%08"PFMT64x,
										r_read_le32 (buf), r_read_le32 (data), addr);
								res = false;
							}
						} else {
							R_LOG_ERROR ("Unsupported patch size %d", (int)size);
							res = false;
						}
					} else if (r_str_startswith (line + 2, "BE ")) {
						if (size == 4) {
							ut8 buf[4] = {0};
							ut32 n = r_num_get (NULL, line + 2 + 3);
							r_write_be32 (buf, n);
							if (memcmp (buf, data, size)) {
								R_LOG_ERROR ("original data does not match at 0x%08"PFMT64x, addr);
								res = false;
							}
						} else {
							R_LOG_ERROR ("Unsupported patch size %d", (int)size);
							res = false;
						}
					} else if (line[2] == '\'') {
						// - '4f f2 ba fc' # bl 0x254526
						if (!verify_hexpairs (line, addr, data, size)) {
							res = false;
						}
					} else if (ishexchar (line[2]) && ishexchar (line[3])) {
						// - 30 (single byte in hex)
// AITODO: use r_hex_pair2bin instead of this awful numget hack
						char byte_str[5] = {'0', 'x', line[2], line[3], '\0'};
						ut8 expected_byte = (ut8)r_num_get (NULL, byte_str);
						if (size == 1) {
							if (data[0] != expected_byte) {
								R_LOG_ERROR ("original data does not match. Expected 0x%02x found 0x%02x at 0x%08"PFMT64x,
									expected_byte, data[0], addr);
								res = false;
							}
						} else {
							R_LOG_ERROR ("Single byte format requires size 1, got %d", (int)size);
							res = false;
						}
					} else {
						R_LOG_ERROR ("Expected LE or BE");
						res = false;
					}
					free (data);
				}
			}
		} else if (r_str_startswith (line, "+ ")) {
			// + LE 0x001b7358 # 1799000 comment after the # symbol, could be assembly
			if (revert) {
				R_LOG_ERROR ("TODO");
			} else {
				ut64 addr = ubpBlock.add_addr;
				ut64 size = ubpBlock.add_size;
				if (r_str_startswith (line + 2, "LE ")) {
					if (size == 4) {
						ut8 buf[4] = {0};
						ut32 n = r_num_get (NULL, line + 2 + 3);
						r_write_le32 (buf, n);
						r_io_write_at (core->io, addr, buf, 4);
					} else {
						R_LOG_ERROR ("Unsupported patch size %d", (int)size);
						res = false;
					}
				} else if (r_str_startswith (line + 2, "BE ")) {
					if (size == 4) {
						ut8 buf[4] = {0};
						ut32 n = r_num_get (NULL, line + 2 + 3);
						r_write_be32 (buf, n);
						r_io_write_at (core->io, addr, buf, 4);
					} else {
						R_LOG_ERROR ("Unsupported patch size %d", (int)size);
						res = false;
					}
				} else if (line[2] == '\'') {
					// + '4f f2 ba fc' # bl 0x254526
					if (!write_hexpairs (core->io, line, addr, size)) {
						res = false;
					}
				} else if (ishexchar (line[2]) && ishexchar (line[3])) {
					// + 30 (single byte in hex)
// AITODO: use r_hex_pair2bin instead of this awful numget hack
					char byte_str[5] = {'0', 'x', line[2], line[3], '\0'};
					ut8 byte_value = (ut8)r_num_get (NULL, byte_str);
					if (size == 1) {
						r_io_write_at (core->io, addr, &byte_value, 1);
					} else {
						R_LOG_ERROR ("Single byte format requires size 1, got %d", (int)size);
						res = false;
					}
				} else {
					R_LOG_ERROR ("Expected LE or BE");
					res = false;
				}
			}
		} else {
			R_LOG_INFO ("Ignored line %s", line);
		}
		free (line);
		line = NULL;
		p = nl + 1;
	}
	free (line);
	free (ubpFileDel.file);
	free (ubpFileDel.tstamp);
	free (ubpFileAdd.file);
	free (ubpFileAdd.tstamp);
	return res;
}
