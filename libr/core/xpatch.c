/* radare - LGPL - Copyright 2025 - pancake */

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
		uf->tstamp = strdup (tab + 1);
	} else {
		uf->file = strdup (line);
		uf->tstamp = NULL;
	}
	r_str_trim (uf->file);
	r_str_trim (uf->tstamp);
	return true;
}

static bool ubp_parseBlock(char *line, UBP_Block *b) {
	// @@ -0x00189ca8,4 +0x00189ca8,4 @@
	// @@ -1612969,char[3] +1612969,char[3] @@
	// @@ -0x00189ca8,char[4] +0x00189ca8,char[4] @@
	// @@ -0x00189ca8,uint32_t[3] +0x00189ca8,uint32_t[3] @@
	// @@ -0x00189ca8,12 +0x00189ca8,12 @@
	char *plus = strchr (line, '+');
	if (!plus) {
		R_LOG_ERROR ("Invalid patch format, Cant find +");
		return false;
	}
	if (!getpair (plus + 1, &b->sub_addr, &b->sub_size)) {
		R_LOG_ERROR ("Invalid patch format, Cant find comma in @@ line");
		return false;
	}
	if (!getpair (line + 3, &b->add_addr, &b->add_size)) {
		R_LOG_ERROR ("Invalid patch format, Cant find comma in @@ line");
		return false;
	}
	if (b->add_size != b->sub_size) {
		// unmatching stuff
	}
	return true;
}

R_API bool r_core_patch_unified(RCore *core, const char *patch, int level, bool revert) {
	R_RETURN_VAL_IF_FAIL (core && patch, false);
	RIODesc *desc = NULL;
	UBP_File ubpFileAdd;
	UBP_File ubpFileDel;
	UBP_Block ubpBlock;
#if 0
	UBP_Entry ubpAdd;
	UBP_Entry ubpDel;
// 	UBP_Error error;
#endif
	char *line = NULL;
	const char *p = patch;
	while (true) {
		const char *nl = strchr (p, '\n');
		if (!nl) {
			break;
		}
		line = r_str_ndup (p, nl - p);
		if (r_str_startswith (line, "--- ")) {
			if (!ubp_parseFile (line, &ubpFileDel, false)) {
				break;
			}
			if (desc) {
				r_io_desc_free (desc);
				desc = NULL;
			}
		} else if (r_str_startswith (line, "+++ ")) {
			if (!ubp_parseFile (line, &ubpFileAdd, true)) {
				break;
			}
			if (desc) {
				R_LOG_WARN ("Invalid patch format, cannot open file twice");

			}
			if (level) {
				R_LOG_TODO ("patch level not implemented yet");
			}
			desc = r_core_file_open (core, ubpFileAdd.file, R_PERM_RW, 0);
			if (!desc) {
				R_LOG_ERROR ("Cannot open %s", ubpFileAdd.file);
				break;
			}
			ut64 size = r_io_desc_size (desc);
			r_io_map_add (core->io, desc->fd, R_PERM_RW, 0, 0, size);
		} else if (r_str_startswith (line, "@@ ")) {
			if (!ubp_parseBlock (line, &ubpBlock)) {
				R_LOG_ERROR ("Invalid patch format, Cant find +");
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
					R_LOG_ERROR ("Cannot allocate %d bytes", size);
					break;
				}
				// TODO: check error
				r_io_read_at (core->io, addr, data, size);
				if (r_str_startswith (line + 2, "LE ")) {
					if (size == 4) {
						ut8 buf[4] = {0};
						ut32 n = r_num_get (NULL, line + 2 + 3);
						r_write_le32 (buf, n);
						if (!memcmp (buf, data, size)) {
							R_LOG_INFO ("ok");
						} else {
							R_LOG_ERROR ("original data does not match. Expected %d found %d at 0x%08"PFMT64x,
									r_read_le32 (buf), r_read_le32 (data), addr);
							break;
						}
					} else {
						R_LOG_ERROR ("Unsupported patch size %d", (int)size);
					}
				} else if (r_str_startswith (line + 2, "BE ")) {
					if (size == 4) {
						ut8 buf[4] = {0};
						ut32 n = r_num_get (NULL, line + 2 + 3);
						r_write_be32 (buf, n);
						if (!memcmp (buf, data, size)) {
							R_LOG_INFO ("ok");
						} else {
							R_LOG_INFO ("");
						}
					} else {
						R_LOG_ERROR ("Unsupported patch size %d", (int)size);
					}
				} else if (line[0] == '\'') {
					// + '4f f2 ba fc' # bl 0x254526
					R_LOG_TODO ("hexpairs");
				} else if (ishexchar (line[0]) && ishexchar (line[1])) {
					// + 30
					R_LOG_TODO ("byte");
				} else {
					R_LOG_ERROR ("Expected LE or BE");
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
					}
				} else if (r_str_startswith (line + 2, "BE ")) {
					if (size == 4) {
						ut8 buf[4] = {0};
						ut32 n = r_num_get (NULL, line + 2 + 3);
						r_write_be32 (buf, n);
						r_io_write_at (core->io, addr, buf, 4);
					} else {
						R_LOG_ERROR ("Unsupported patch size %d", (int)size);
					}
				} else if (line[0] == '\'') {
					// + '4f f2 ba fc' # bl 0x254526
					R_LOG_TODO ("hexpairs");
				} else if (ishexchar (line[0]) && ishexchar (line[1])) {
					// + 30
					R_LOG_TODO ("byte");
				} else {
					R_LOG_ERROR ("Expected LE or BE");
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
	return true;
}
