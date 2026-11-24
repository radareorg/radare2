/* radare - LGPL - Copyright 2026 - pancake */

#include <errno.h>

static bool binary_number(const char *text, const char **end, ut64 *number) {
	if (*text < '0' || *text > '9') {
		return false;
	}
	char *tail;
	errno = 0;
	const int base = r_str_startswith (text, "0x")? 16: 10;
	*number = strtoull (text, &tail, base);
	*end = tail;
	return tail != text && !errno;
}

static bool binary_range(const char *text, ut64 *offset, ut64 *size) {
	const char *end;
	return binary_number (text, &end, offset) && *end == ','
		&& binary_number (end + 1, &end, size)
		&& (!*end || !strcmp (end, ",") || !strcmp (end, " @@"));
}

static bool binary_bytes(char *text, ut8 **bytes, size_t *length) {
	size_t size = strlen (text);
	if (size >= 2 && text[0] == '\'' && text[size - 1] == '\'') {
		text[size - 1] = 0;
		text++;
		size -= 2;
	}
	if ((size & 1) || strspn (text, "0123456789abcdefABCDEF") != size || size / 2 > ST32_MAX) {
		return false;
	}
	*length = 0;
	*bytes = size? r_hex_str2bin_dup (text, length): NULL;
	return !size || *bytes;
}

static bool binary_edit(RIO *io, ut64 offset, ut64 remove, ut64 insert, const ut8 *data) {
	RIODesc *desc = io->desc;
	const ut64 size = r_io_desc_size (desc);
	if (size == UT64_MAX || offset > size || remove > size - offset
			|| insert > ST32_MAX || remove > ST32_MAX || insert > UT64_MAX - (size - remove)) {
		return false;
	}
	const ut64 tail = size - offset - remove;
	const ut64 new_size = size - remove + insert;
	if (new_size > size) {
		const st64 growth = insert - remove;
		if (!r_io_desc_resize (desc, new_size)
				|| (tail && !r_io_shift (io, offset + remove, new_size, growth))) {
			return false;
		}
	} else if (new_size < size) {
		const st64 shrink = remove - insert;
		if ((tail && !r_io_shift (io, offset + insert, size, -shrink))
				|| !r_io_desc_resize (desc, new_size)) {
			return false;
		}
	}
	return !data || r_io_desc_write_at (desc, offset, data, insert) == insert;
}

static bool binary_matches(RIODesc *desc, ut64 offset, const ut8 *data, size_t len) {
	const ut64 size = r_io_desc_size (desc);
	if (size == UT64_MAX || offset > size || len > size - offset) {
		return false;
	}
	ut8 buffer[4096];
	while (len) {
		const int chunk = R_MIN (len, sizeof (buffer));
		if (r_io_desc_read_at (desc, offset, buffer, chunk) != chunk || memcmp (data, buffer, chunk)) {
			return false;
		}
		data += chunk;
		offset += chunk;
		len -= chunk;
	}
	return true;
}

static char *binary_line(RListIter **iter) {
	if (!*iter) {
		return NULL;
	}
	char *line = (*iter)->data;
	*iter = (*iter)->n;
	return line;
}

static bool binary_unified(RIO *io, RListIter *iter) {
	const char *label = binary_line (&iter);
	if (!label || !r_str_startswith (label, "+++ ")) {
		return false;
	}
	ut64 previous_old = 0, previous_new = 0;
	char *header;
	while ((header = binary_line (&iter))) {
		if (!*header) {
			continue;
		}
		char *old = strstr (header, " -");
		char *next = old? strstr (old + 2, " +"): NULL;
		if (!r_str_startswith (header, "@@ ") || !next) {
			return false;
		}
		*next = 0;
		ut64 old_offset, new_offset, old_size, new_size;
		if (!binary_range (old + 2, &old_offset, &old_size)
				|| !binary_range (next + 2, &new_offset, &new_size)
				|| old_offset < previous_old || new_offset < previous_new
				|| old_offset - previous_old != new_offset - previous_new
				|| old_size > UT64_MAX - old_offset || new_size > UT64_MAX - new_offset) {
			return false;
		}
		char *removed = binary_line (&iter);
		char *inserted = binary_line (&iter);
		if (!removed || !inserted || *removed != '-' || *inserted != '+') {
			return false;
		}
		ut8 *before = NULL, *after = NULL;
		size_t before_len, after_len;
		const bool ok = binary_bytes (removed + (removed[1] == ' '? 2: 1), &before, &before_len)
			&& binary_bytes (inserted + (inserted[1] == ' '? 2: 1), &after, &after_len)
			&& before_len == old_size && after_len == new_size
			&& binary_matches (io->desc, new_offset, before, before_len)
			&& binary_edit (io, new_offset, old_size, new_size, after);
		free (before);
		free (after);
		if (!ok) {
			return false;
		}
		previous_old = old_offset + old_size;
		previous_new = new_offset + new_size;
	}
	return true;
}

static bool binary_write(RIO *io, char *line) {
	const char *end;
	char *address;
	char *bytes = NULL;
	ut64 offset, count = 0;
	if (r_str_startswith (line, "wx ") || r_str_startswith (line, "r+") || r_str_startswith (line, "r-")) {
		address = strstr (line, " @ ");
		if (!address) {
			return false;
		}
		*address = 0;
		if (!binary_number (address + 3, &end, &offset) || *end) {
			return false;
		}
		if (*line == 'r') {
			if (!binary_number (line + 2, &end, &count) || *end || !count) {
				return false;
			}
			return line[1] == '+'? binary_edit (io, offset, 0, count, NULL): binary_edit (io, offset, count, 0, NULL);
		}
		bytes = line + 3;
	} else {
		if (!binary_number (line, &end, &offset) || *end != ' ') {
			return false;
		}
		bytes = (char *)r_str_trim_head_ro (end);
	}
	ut8 *data = NULL;
	size_t len;
	const bool ok = binary_bytes (bytes, &data, &len) && len && binary_edit (io, offset, len, len, data);
	free (data);
	return ok;
}

static bool binary_apply(RIO *io, RList *lines) {
	RListIter *iter = r_list_iterator (lines);
	char *line;
	while ((line = binary_line (&iter))) {
		if (!*line || *line == '#') {
			continue;
		}
		if (r_str_startswith (line, "--- ")) {
			return binary_unified (io, iter);
		}
		if (!binary_write (io, line)) {
			return false;
		}
	}
	return true;
}

static int rapatch_binary(const char *patch, const char *file) {
	if (!file || !r_file_is_regular (file)) {
		R_LOG_ERROR ("Binary patch mode requires a local target file");
		return 1;
	}
	size_t size;
	char *text = r_file_slurp (patch, &size);
	if (!text || memchr (text, 0, size)) {
		R_LOG_ERROR ("Cannot read patch as text");
		free (text);
		return 1;
	}
	RList *lines = r_str_split_duplist (text, "\n", true);
	free (text);
	RIO *io = r_io_new ();
	RIODesc *desc = io? r_io_open_nomap (io, file, R_PERM_RW, 0): NULL;
	bool ok = false;
	if (desc && lines && r_io_use_fd (io, desc->fd)) {
		io->va = false;
		ok = binary_apply (io, lines);
	}
	r_io_free (io);
	r_list_free (lines);
	if (!ok) {
		R_LOG_ERROR ("Cannot apply binary patch. Check its format and original bytes");
	}
	return ok? 0: 1;
}
