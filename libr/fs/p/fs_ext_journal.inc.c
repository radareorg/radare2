/* radare - LGPL - Copyright 2026 - pancake */

#define EXT_JOURNAL_MAGIC 0xc03b3998U
#define EXT_JOURNAL_LIMIT 0x100000

typedef struct {
	ut64 block;
	ut32 journal_block;
	ut32 flags;
	ut32 data_crc;
	bool revoked;
	bool revoke_record;
} ExtJournalTag;

typedef struct {
	RFSRoot *root;
	GrubFS *file;
	ut32 block_size, first, length, features, compat;
	ut64 blocks;
	ut8 uuid[16];
	ut8 *scratch;
	RConsBind *console;
	bool stopped;
	bool report_invalid;
	bool active;
} ExtJournal;

typedef bool (*ExtJournalCb)(ExtJournal *journal, ut32 sequence, ut32 start, const ExtJournalTag *tag, void *user);

static ut32 ext_journal_crc(const ut8 *data, ut32 size) {
	return ext2_crc32c (UT32_MAX, data, size);
}

static bool ext_journal_read(ExtJournal *j, ut32 block, ut8 *data) {
	if (block >= j->length) {
		return false;
	}
	grubfs_bind_io (NULL, j->root->delta);
	j->file->file->offset = (ut64)block * j->block_size;
	return j->file->file->fs->read (j->file->file, (char *)data, j->block_size) == j->block_size;
}

static void ext_journal_close(ExtJournal *j) {
	if (j->file) {
		if (j->file->file->data) {
			j->file->file->fs->close (j->file->file);
		}
		grubfs_free (j->file);
	}
	free (j->scratch);
}

static bool ext_journal_open(RFSRoot *root, ExtJournal *j) {
	ut8 sb[1024], super[1024];
	memset (j, 0, sizeof (*j));
	j->root = root;
	if (root->delta > UT64_MAX - 2048 || root->iob.read_at (root->iob.io, root->delta + 1024, sb, sizeof (sb)) != sizeof (sb)
			|| r_read_le16 (sb + 56) != 0xef53 || !(r_read_le32 (sb + 92) & 4)
			|| r_read_le32 (sb + 24) > 6 || r_read_le32 (sb + 228)) {
		R_LOG_ERROR ("No supported internal ext3/ext4 journal");
		return false;
	}
	ut32 ino = r_read_le32 (sb + 224);
	if (!ino || ino > r_read_le32 (sb) || ino > INT_MAX) {
		return false;
	}
	j->block_size = 1024U << r_read_le32 (sb + 24);
	j->blocks = r_read_le32 (sb + 4);
	if (r_read_le32 (sb + 96) & 128) {
		j->blocks |= (ut64)r_read_le32 (sb + 336) << 32;
	}
	if (!j->blocks || j->blocks > (UT64_MAX - root->delta) / j->block_size) {
		return false;
	}
	j->file = grubfs_new (&grub_ext2_fs, &root->iob);
	if (!j->file) {
		return false;
	}
	grubfs_bind_io (NULL, root->delta);
	if (grub_ext2_open_inode (j->file->file, ino, NULL)) {
		goto fail;
	}
	j->file->file->offset = 0;
	if (j->file->file->fs->read (j->file->file, (char *)super, sizeof (super)) != sizeof (super)
			|| r_read_be32 (super) != EXT_JOURNAL_MAGIC || (r_read_be32 (super + 4) != 3 && r_read_be32 (super + 4) != 4)
			|| r_read_be32 (super + 12) != j->block_size) {
		goto fail;
	}
	j->length = r_read_be32 (super + 16);
	j->first = r_read_be32 (super + 20);
	j->active = r_read_be32 (super + 28) != 0;
	if (!j->first || j->first >= j->length || j->length > j->file->file->size / j->block_size) {
		goto fail;
	}
	if (r_read_be32 (super + 4) == 4) {
		j->compat = r_read_be32 (super + 36);
		j->features = r_read_be32 (super + 40);
		if ((j->compat & ~1U) || (j->features & ~31U) || r_read_be32 (super + 44)
				|| ((j->features & 4) && !(j->features & 24) && !j->compat)
				|| r_read_be32 (super + 64) > 1 || ((j->features & 24) == 24) || ((j->features & 24) && j->compat)) {
			R_LOG_ERROR ("Unsupported journal features (including fast commits)");
			goto fail;
		}
	}
	memcpy (j->uuid, r_read_be32 (super + 4) == 3? sb + 104: super + 48, 16);
	if (memcmp (j->uuid, sb + 104, 16)) {
		R_LOG_ERROR ("Journal UUID does not match the filesystem");
		goto fail;
	}
	if (j->features & 24) {
		ut32 expected = r_read_be32 (super + 252);
		r_write_be32 (super + 252, 0);
		if (super[80] != 4 || expected != ext_journal_crc (super, sizeof (super))) {
			R_LOG_ERROR ("Invalid journal superblock checksum");
			goto fail;
		}
	}
	j->scratch = malloc (j->block_size + 20);
	if (!j->scratch) {
		goto fail;
	}
	return true;
 fail:
	ext_journal_close (j);
	j->file = NULL;
	return false;
}

static ut32 ext_journal_next(ExtJournal *j, ut32 block) {
	return block + 1 == j->length? j->first: block + 1;
}

static bool ext_journal_metadata_crc(ExtJournal *j, ut8 *data, ut32 offset) {
	if (!(j->features & 24)) {
		return true;
	}
	ut32 expected = r_read_be32 (data + offset);
	r_write_be32 (data + offset, 0);
	memcpy (j->scratch, j->uuid, 16);
	memcpy (j->scratch + 16, data, j->block_size);
	ut32 actual = ext_journal_crc (j->scratch, j->block_size + 16);
	r_write_be32 (data + offset, expected);
	return actual == expected;
}

static ut32 ext_journal_crc32(ut32 crc, const ut8 *data, ut32 size) {
	ut32 i;
	for (i = 0; i < size; i++) {
		crc ^= (ut32)data[i] << 24;
		unsigned bit;
		for (bit = 0; bit < 8; bit++) {
			crc = (crc << 1) ^ ((crc & 0x80000000)? 0x04c11db7: 0);
		}
	}
	return crc;
}

static bool ext_journal_tags(ExtJournal *j, ut8 *data, ut32 sequence, ut32 *cursor, ut32 *used, ut32 *crc, RList *tags, ut8 *payload) {
	if (!ext_journal_metadata_crc (j, data, j->block_size - 4)) {
		return false;
	}
	if (j->compat & 1) {
		*crc = ext_journal_crc32 (*crc, data, j->block_size);
	}
	ut32 size = j->features & 16? 16: (j->features & 2? 12: 8) + (j->features & 8? 2: 0);
	ut32 offset = 12, end = j->block_size - (j->features & 24? 4: 0);
	while (offset <= end && size <= end - offset) {
		ut64 block = r_read_be32 (data + offset);
		ut32 flags = j->features & 16? r_read_be32 (data + offset + 4): r_read_be16 (data + offset + 6);
		if (flags & ~15U) {
			return false;
		}
		if (j->features & 2) {
			block |= (ut64)r_read_be32 (data + offset + 8) << 32;
		} else if ((j->features & 16) && r_read_be32 (data + offset + 8)) {
			return false;
		}
		ut32 checksum = j->features & 16? r_read_be32 (data + offset + 12): r_read_be16 (data + offset + 4);
		offset += size;
		if (!(flags & 2)) {
			if (16 > end - offset || memcmp (data + offset, j->uuid, 16)) {
				return false;
			}
			offset += 16;
		}
		if (block >= j->blocks || *used >= j->length - j->first || *used >= EXT_JOURNAL_LIMIT
				|| !ext_journal_read (j, *cursor, payload)) {
			return false;
		}
		if (j->compat & 1) {
			*crc = ext_journal_crc32 (*crc, payload, j->block_size);
		}
		if (j->features & 24) {
			memcpy (j->scratch, j->uuid, 16);
			r_write_be32 (j->scratch + 16, sequence);
			memcpy (j->scratch + 20, payload, j->block_size);
			ut32 actual = ext_journal_crc (j->scratch, j->block_size + 20);
			if ((j->features & 16? actual: actual & 0xffff) != checksum) {
				return false;
			}
		}
		ExtJournalTag *tag = R_NEW0 (ExtJournalTag);
		tag->block = block;
		tag->journal_block = *cursor;
		tag->flags = flags;
		tag->data_crc = ext_journal_crc (payload, j->block_size);
		if (!r_list_append (tags, tag)) {
			free (tag);
			return false;
		}
		*cursor = ext_journal_next (j, *cursor);
		(*used)++;
		if (flags & 8) {
			return true;
		}
	}
	return false;
}

static bool ext_journal_transaction(ExtJournal *j, ut32 start, ExtJournalCb cb, void *user, ut32 *consumed) {
	ut8 *header = malloc (j->block_size), *payload = malloc (j->block_size);
	RList *tags = r_list_newf (free);
	RBitset *revoked = r_bitset_new ();
	bool valid = false;
	ut32 cursor = start, used = 0, sequence = 0, crc = UT32_MAX;
	if (!header || !payload || !tags || !revoked) {
		goto done;
	}
	while (used < j->length - j->first && used < EXT_JOURNAL_LIMIT) {
		if (j->console && j->console->is_breaked && j->console->is_breaked (j->console->cons)) {
			j->stopped = true;
			break;
		}
		if (!ext_journal_read (j, cursor, header) || r_read_be32 (header) != EXT_JOURNAL_MAGIC) {
			break;
		}
		if (!used) {
			sequence = r_read_be32 (header + 8);
		} else if (r_read_be32 (header + 8) != sequence) {
			break;
		}
		ut32 header_block = cursor;
		ut32 type = r_read_be32 (header + 4);
		cursor = ext_journal_next (j, cursor);
		used++;
		if (type == 1) {
			if (!ext_journal_tags (j, header, sequence, &cursor, &used, &crc, tags, payload)) {
				break;
			}
		} else if (type == 5) {
			ut32 bytes = r_read_be32 (header + 12), width = j->features & 2? 8: 4;
			ut32 limit = j->block_size - (j->features & 24? 4: 0), offset;
			if (!(j->features & 1) || bytes < 16 || bytes > limit || (bytes - 16) % width
					|| !ext_journal_metadata_crc (j, header, j->block_size - 4)) {
				break;
			}
			for (offset = 16; offset < bytes; offset += width) {
				ut64 block = width == 8? r_read_be64 (header + offset): r_read_be32 (header + offset);
				if (block >= j->blocks || (!r_bitset_test (revoked, block) && !r_bitset_set (revoked, block))) {
					goto done;
				}
				ExtJournalTag *tag = R_NEW0 (ExtJournalTag);
				tag->block = block;
				tag->journal_block = header_block;
				tag->revoke_record = true;
				if (!r_list_append (tags, tag)) {
					free (tag);
					goto done;
				}
			}
		} else if (type == 2) {
			if (!ext_journal_metadata_crc (j, header, 16)
					|| ((j->compat & 1) && (header[12] != 1 || header[13] != 4 || r_read_be32 (header + 16) != crc))) {
				break;
			}
			RListIter *iter;
			ExtJournalTag *tag;
			r_list_foreach (tags, iter, tag) {
				tag->revoked = tag->revoke_record || (tag->flags & 4) || r_bitset_test (revoked, tag->block);
				if (!cb (j, sequence, start, tag, user)) {
					j->stopped = true;
					goto done;
				}
			}
			valid = true;
			break;
		} else {
			break;
		}
	}
 done:
	*consumed = valid? used: 1;
	r_bitset_free (revoked);
	r_list_free (tags);
	free (header);
	free (payload);
	return valid;
}

static bool ext_journal_scan_raw(ExtJournal *j, ExtJournalCb cb, void *user) {
	ut8 header[12];
	ut32 block = j->first;
	bool ok = true;
	while (block < j->length) {
		if (j->console && j->console->is_breaked && j->console->is_breaked (j->console->cons)) {
			return false;
		}
		grubfs_bind_io (NULL, j->root->delta);
		j->file->file->offset = (ut64)block * j->block_size;
		if (j->file->file->fs->read (j->file->file, (char *)header, sizeof (header)) != sizeof (header)) {
			ok = false;
			break;
		}
		ut32 consumed = 1;
		if (r_read_be32 (header) == EXT_JOURNAL_MAGIC && (r_read_be32 (header + 4) == 1 || r_read_be32 (header + 4) == 5)) {
			if (!ext_journal_transaction (j, block, cb, user, &consumed)) {
				if (j->stopped) {
					return false;
				}
				if (j->report_invalid) {
					R_LOG_WARN ("Ignoring incomplete or invalid journal transaction at block %u", block);
				}
			}
		}
		if (consumed > j->length - block) {
			break;
		}
		block += consumed;
	}
	return ok;
}

typedef struct {
	HtUP *revoked;
	RBitset *seen;
	ExtJournalCb cb;
	void *user;
	ut32 revokes;
} ExtJournalScan;

static void ext_journal_revoke_free(HtUPKv *kv) {
	r_bitset_free (kv->value);
}

static bool ext_journal_collect_revoke(ExtJournal *j, ut32 sequence, ut32 start, const ExtJournalTag *tag, void *user) {
	ExtJournalScan *scan = user;
	if (!tag->revoked) {
		return true;
	}
	if (scan->revokes++ >= EXT_JOURNAL_LIMIT) {
		return false;
	}
	RBitset *blocks = ht_up_find (scan->revoked, sequence, NULL);
	if (!blocks) {
		blocks = r_bitset_new ();
		if (!blocks || !ht_up_insert (scan->revoked, sequence, blocks)) {
			r_bitset_free (blocks);
			return false;
		}
	}
	return r_bitset_test (blocks, tag->block) || r_bitset_set (blocks, tag->block);
}

static bool ext_journal_emit(ExtJournal *j, ut32 sequence, ut32 start, const ExtJournalTag *tag, void *user) {
	ExtJournalScan *scan = user;
	if (!tag->revoke_record) {
		if (r_bitset_test (scan->seen, tag->journal_block)) {
			return true;
		}
		if (!r_bitset_set (scan->seen, tag->journal_block)) {
			return false;
		}
	}
	ExtJournalTag record = *tag;
	RBitset *blocks = ht_up_find (scan->revoked, sequence, NULL);
	record.revoked |= blocks && r_bitset_test (blocks, tag->block);
	return scan->cb (j, sequence, start, &record, scan->user);
}

static bool ext_journal_scan(ExtJournal *j, ExtJournalCb cb, void *user) {
	ExtJournalScan scan = { .cb = cb, .user = user };
	scan.revoked = ht_up_new (NULL, ext_journal_revoke_free, NULL);
	scan.seen = r_bitset_new ();
	j->report_invalid = false;
	bool ok = scan.revoked && scan.seen && ext_journal_scan_raw (j, ext_journal_collect_revoke, &scan);
	j->report_invalid = true;
	if (ok) {
		ok = ext_journal_scan_raw (j, ext_journal_emit, &scan);
	}
	ht_up_free (scan.revoked);
	r_bitset_free (scan.seen);
	return ok;
}

static bool ext_journal_payload(ExtJournal *j, const ExtJournalTag *tag, ut8 *data) {
	if (tag->revoked || !ext_journal_read (j, tag->journal_block, data)
			|| ext_journal_crc (data, j->block_size) != tag->data_crc) {
		return false;
	}
	if (tag->flags & 1) {
		r_write_be32 (data, EXT_JOURNAL_MAGIC);
	}
	return true;
}

typedef struct {
	ut64 first, end, inode_end;
	ut32 inode;
} ExtJournalTable;

static int ext_journal_table_compare(const void *a, const void *b) {
	const ExtJournalTable *left = a, *right = b;
	return left->first < right->first? -1: left->first > right->first;
}

static ExtJournalTable *ext_journal_tables(ExtJournal *j, ut32 *count, ut32 *inode_size) {
	ut8 sb[1024];
	RFSRoot *root = j->root;
	if (root->iob.read_at (root->iob.io, root->delta + 1024, sb, sizeof (sb)) != sizeof (sb)
			|| (r_read_le32 (sb + 96) & 16)) {
		return NULL;
	}
	ut32 inodes = r_read_le32 (sb);
	ut32 per_group = r_read_le32 (sb + 40);
	*inode_size = r_read_le32 (sb + 76)? r_read_le16 (sb + 88): 128;
	ut32 descriptor_size = r_read_le32 (sb + 96) & 128? r_read_le16 (sb + 254): 32;
	if (!inodes || !per_group || per_group > j->block_size * 8 || *inode_size < 128 || *inode_size > j->block_size
			|| (*inode_size & (*inode_size - 1)) || descriptor_size < 32 || descriptor_size > j->block_size
			|| ((r_read_le32 (sb + 96) & 128) && descriptor_size < 64)) {
		return NULL;
	}
	ut64 groups = ((ut64)inodes + per_group - 1) / per_group, bytes;
	if (groups > EXT_JOURNAL_LIMIT || r_mul_overflow_ut64 (groups, sizeof (ExtJournalTable), &bytes) || bytes > SIZE_MAX) {
		return NULL;
	}
	ExtJournalTable *tables = malloc (bytes);
	if (!tables) {
		return NULL;
	}
	ut64 base = ((ut64)r_read_le32 (sb + 20) + 1) * j->block_size;
	ut32 group;
	for (group = 0; group < groups; group++) {
		ut8 desc[64];
		ut64 offset = base + (ut64)group * descriptor_size;
		ut32 nread = R_MIN (descriptor_size, sizeof (desc));
		if (offset > j->blocks * j->block_size || nread > j->blocks * j->block_size - offset
				|| root->iob.read_at (root->iob.io, root->delta + offset, desc, nread) != nread) {
			goto fail;
		}
		ut64 table = r_read_le32 (desc + 8);
		if (r_read_le32 (sb + 96) & 128) {
			table |= (ut64)r_read_le32 (desc + 40) << 32;
		}
		ut64 start_inode = (ut64)group * per_group;
		ut64 entries = R_MIN ((ut64)per_group, inodes - start_inode);
		ut64 blocks = (entries * *inode_size + j->block_size - 1) / j->block_size;
		if (!table || table >= j->blocks || blocks > j->blocks - table) {
			goto fail;
		}
		tables[group].first = table;
		tables[group].end = table + blocks;
		tables[group].inode = start_inode + 1;
		tables[group].inode_end = start_inode + entries + 1;
	}
	qsort (tables, groups, sizeof (*tables), ext_journal_table_compare);
	for (group = 1; group < groups; group++) {
		if (tables[group].first < tables[group - 1].end) {
			goto fail;
		}
	}
	*count = groups;
	return tables;
 fail:
	free (tables);
	return NULL;
}

static ExtJournalTable *ext_journal_table_find(ExtJournalTable *tables, ut32 count, ut64 block) {
	ut32 low = 0, high = count;
	while (low < high) {
		ut32 mid = low + (high - low) / 2;
		if (tables[mid].end <= block) {
			low = mid + 1;
		} else {
			high = mid;
		}
	}
	return low < count && tables[low].first <= block? tables + low: NULL;
}

static void ext_journal_inode_json(PJ *pj, const ut8 *inode, ut64 id, ut32 sequence) {
	pj_o (pj);
	pj_kn (pj, "inode", id);
	pj_kn (pj, "sequence", sequence);
	pj_kn (pj, "size", ext2_size (inode));
	pj_kn (pj, "mode", r_read_le16 (inode));
	pj_kn (pj, "links", r_read_le16 (inode + 26));
	pj_kn (pj, "mtime", r_read_le32 (inode + 16));
	pj_kn (pj, "dtime", r_read_le32 (inode + 20));
	pj_kn (pj, "generation", r_read_le32 (inode + 100));
	pj_kn (pj, "flags", r_read_le32 (inode + 32));
	pj_end (pj);
}

typedef struct {
	RFS *fs;
	PJ *json;
	bool extract, found, failed, inodes, filter_sequence;
	ExtJournalTable *tables;
	ut32 table_count, inode_size;
	ut32 sequence;
	ut64 block;
	ut32 source;
	ut8 *data;
} ExtJournalOutput;

static bool ext_journal_record(ExtJournal *j, ut32 sequence, ut32 start, const ExtJournalTag *tag, void *user) {
	ExtJournalOutput *out = user;
	if (out->inodes) {
		if (tag->revoked || (out->filter_sequence && sequence != out->sequence)) {
			return true;
		}
		ExtJournalTable *table = ext_journal_table_find (out->tables, out->table_count, tag->block);
		if (!table) {
			return true;
		}
		if (!ext_journal_payload (j, tag, out->data)) {
			out->failed = true;
			return false;
		}
		ut64 id = table->inode + (tag->block - table->first) * (j->block_size / out->inode_size);
		ut32 offset;
		for (offset = 0; offset < j->block_size && id < table->inode_end; offset += out->inode_size, id++) {
			const ut8 *inode = out->data + offset;
			ut16 mode = r_read_le16 (inode) & 0xf000;
			if (mode != 0x8000 && mode != 0x4000 && mode != 0xa000
					&& mode != 0x1000 && mode != 0x2000 && mode != 0x6000 && mode != 0xc000) {
				continue;
			}
			if (out->json) {
				ext_journal_inode_json (out->json, inode, id, sequence);
			} else {
				out->fs->csb.cb_printf (out->fs->csb.cons, "%u %"PFMT64u" %"PFMT64u" 0x%x\n", sequence, id, ext2_size (inode), r_read_le16 (inode));
			}
		}
		return true;
	}
	if (out->extract) {
		if (sequence != out->sequence || tag->block != out->block) {
			return true;
		}
		if (tag->revoked) {
			out->failed = true;
			return true;
		}
		if (out->found && out->source != tag->journal_block) {
			R_LOG_ERROR ("Ambiguous journal block version");
			out->failed = true;
			return false;
		}
		if (!ext_journal_payload (j, tag, out->data)) {
			out->failed = true;
			return false;
		}
		out->source = tag->journal_block;
		out->found = true;
		return true;
	}
	if (out->json) {
		pj_o (out->json);
		pj_kn (out->json, "sequence", sequence);
		pj_kn (out->json, "block", tag->block);
		pj_kn (out->json, "offset", j->root->delta + tag->block * j->block_size);
		pj_kn (out->json, "journal_block", tag->journal_block);
		pj_ks (out->json, "kind", tag->revoke_record? "revoke": "data");
		pj_kb (out->json, "revoked", tag->revoked);
		pj_kb (out->json, "checksummed", (j->features & 24) || (j->compat && !tag->revoke_record));
		pj_end (out->json);
	} else {
		out->fs->csb.cb_printf (out->fs->csb.cons, "%u 0x%"PFMT64x" %u %s\n",
			sequence, tag->block, tag->journal_block, tag->revoked? "revoked": "committed");
	}
	return true;
}

static bool ext_journal_inode_location(ExtJournal *j, ut64 id, ut32 *skip, ut32 *size, ut64 *block) {
	ut8 sb[1024], desc[64];
	RFSRoot *root = j->root;
	if (root->iob.read_at (root->iob.io, root->delta + 1024, sb, sizeof (sb)) != sizeof (sb)
			|| !id || id > r_read_le32 (sb) || (r_read_le32 (sb + 96) & 16)) {
		return false;
	}
	ut32 per_group = r_read_le32 (sb + 40);
	ut32 inode_size = r_read_le32 (sb + 76)? r_read_le16 (sb + 88): 128;
	ut32 desc_size = r_read_le32 (sb + 96) & 128? r_read_le16 (sb + 254): 32;
	if (!per_group || per_group > j->block_size * 8 || inode_size < 128 || inode_size > j->block_size
			|| (inode_size & (inode_size - 1)) || desc_size < 32 || desc_size > j->block_size
			|| ((r_read_le32 (sb + 96) & 128) && desc_size < 64)) {
		return false;
	}
	ut64 offset = ((ut64)r_read_le32 (sb + 20) + 1) * j->block_size + ((id - 1) / per_group) * desc_size;
	ut64 bytes = j->blocks * j->block_size;
	ut32 nread = R_MIN (desc_size, sizeof (desc));
	if (offset > bytes || nread > bytes - offset
			|| root->iob.read_at (root->iob.io, root->delta + offset, desc, nread) != nread) {
		return false;
	}
	ut64 table = r_read_le32 (desc + 8);
	if (r_read_le32 (sb + 96) & 128) {
		table |= (ut64)r_read_le32 (desc + 40) << 32;
	}
	ut64 relative = ((id - 1) % per_group) * inode_size;
	if (!table || table >= j->blocks || relative > bytes - table * j->block_size
			|| inode_size > bytes - table * j->block_size - relative) {
		return false;
	}
	offset = table * j->block_size + relative;
	*block = offset / j->block_size;
	*skip = offset % j->block_size;
	*size = inode_size;
	return *size <= j->block_size - *skip;
}

static void ext_journal_inode_info(RFS *fs, const ut8 *inode, ut64 id, ut32 sequence, bool json) {
	ut64 size = ext2_size (inode);
	if (json) {
		PJ *pj = pj_new ();
		ext_journal_inode_json (pj, inode, id, sequence);
		fs->csb.cb_printf (fs->csb.cons, "%s\n", pj_string (pj));
		pj_free (pj);
	} else {
		fs->csb.cb_printf (fs->csb.cons, "inode %"PFMT64u" sequence %u size %"PFMT64u" mode 0x%x generation %u\n",
			id, sequence, size, r_read_le16 (inode), r_read_le32 (inode + 100));
	}
}

typedef struct {
	ExtJournalTag tag;
	ut32 sequence;
} ExtJournalVersion;

typedef struct {
	ExtJournal *journal;
	HtUP *versions;
	ut32 sequence, count;
	bool selected, reading, failed;
	ut8 *data;
	Ext2Geometry *current;
	RBitset *owners, *later;
	ut64 inode_id;
	ut32 generation;
	bool eligible, checked, used_current;
} ExtJournalHistory;

static void ext_journal_version_free(HtUPKv *kv) {
	free (kv->value);
}

static bool ext_journal_version(ExtJournal *j, ut32 sequence, ut32 start, const ExtJournalTag *tag, void *user) {
	ExtJournalHistory *history = user;
	ut32 age = history->sequence - sequence;
	if (age > INT_MAX) {
		if (history->later && !r_bitset_test (history->later, tag->block)
				&& (age == 0x80000000U || history->count++ >= EXT_JOURNAL_LIMIT || !r_bitset_set (history->later, tag->block))) {
			history->failed = true;
			return false;
		}
		return true;
	}
	if (!age) {
		history->selected = true;
	}
	ExtJournalVersion *version = ht_up_find (history->versions, tag->block, NULL);
	if (version) {
		ut32 previous_age = history->sequence - version->sequence;
		if (previous_age < age || (previous_age == age && version->tag.revoked)) {
			return true;
		}
		if (previous_age == age && !tag->revoked && !version->tag.revoked
				&& tag->journal_block != version->tag.journal_block) {
			history->failed = true;
			return false;
		}
	} else {
		if (history->count++ >= EXT_JOURNAL_LIMIT) {
			history->failed = true;
			return false;
		}
		version = R_NEW0 (ExtJournalVersion);
		if (!ht_up_insert (history->versions, tag->block, version)) {
			free (version);
			history->failed = true;
			return false;
		}
	}
	version->sequence = sequence;
	version->tag = *tag;
	return true;
}

static bool ext_journal_current_block(ExtJournalHistory *history, ut64 block) {
	Ext2Geometry *g = history->current;
	if (!g || !history->eligible || r_bitset_test (history->later, block)) {
		return false;
	}
	if (!history->checked) {
		history->checked = true;
		ut8 inode[128];
		if (ext2_allocated (g, history->inode_id, true) == 0 && ext2_inode (g, history->inode_id, inode)
				&& r_read_le32 (inode + 100) == history->generation) {
			history->owners = ext2_owners (g);
		}
	}
	return history->owners && !r_bitset_test (history->owners, block) && ext2_allocated (g, block, false) == 0;
}

static int ext_journal_history_read(RIO *io, ut64 address, ut8 *buf, int len) {
	ExtJournalHistory *history = (ExtJournalHistory *)io;
	ExtJournal *j = history->journal;
	if (!history->reading) {
		return j->root->iob.read_at (j->root->iob.io, address, buf, len);
	}
	if (len < 0 || address < j->root->delta) {
		return -1;
	}
	ut64 relative = address - j->root->delta;
	int done = 0;
	while (done < len) {
		ut64 block = relative / j->block_size;
		ut32 offset = relative % j->block_size;
		ExtJournalVersion *version = ht_up_find (history->versions, block, NULL);
		if (version) {
			if (!ext_journal_payload (j, &version->tag, history->data)) {
				return -1;
			}
		} else {
			if (!ext_journal_current_block (history, block)
					|| !ext2_disk (history->current, block * j->block_size, history->data, j->block_size)) {
				return -1;
			}
			history->used_current = true;
		}
		int chunk = R_MIN (len - done, j->block_size - offset);
		memcpy (buf + done, history->data + offset, chunk);
		done += chunk;
		relative += chunk;
	}
	return done;
}

typedef struct {
	RFS *fs;
	Ext2Geometry *geometry;
	const char *output;
	ut8 *data;
	ut64 written;
	bool sparse_known;
} ExtJournalRecovery;

static int ext_journal_recover_block(ut64 block, ut64 logical, ut64 size, unsigned depth, ut32 flags, void *user) {
	ExtJournalRecovery *recovery = user;
	if (depth) {
		return R_FS_WALK_COMPLETE;
	}
	if (logical != recovery->written || (!block && !recovery->sparse_known)) {
		return R_FS_WALK_ERROR;
	}
	RFS *fs = recovery->fs;
	ut64 done = 0;
	while (done < size) {
		if (fs->csb.is_breaked && fs->csb.is_breaked (fs->csb.cons)) {
			return R_FS_WALK_STOPPED;
		}
		int chunk = R_MIN ((ut64)recovery->geometry->block_size, size - done);
		if (block && !(flags & R_FS_RANGE_UNWRITTEN)) {
			if (!ext2_disk (recovery->geometry, block * recovery->geometry->block_size, recovery->data, chunk)) {
				return R_FS_WALK_ERROR;
			}
		} else {
			memset (recovery->data, 0, chunk);
		}
		bool ok = !strcmp (recovery->output, "-")?
			fs->csb.cb_write (fs->csb.cons, (const char *)recovery->data, chunk): r_file_dump (recovery->output, recovery->data, chunk, true);
		if (!ok) {
			return R_FS_WALK_ERROR;
		}
		done += chunk;
		recovery->written += chunk;
	}
	return R_FS_WALK_COMPLETE;
}

static bool ext_journal_recover_free(RFS *fs, ExtJournalHistory *history, ut8 *inode, ut32 inode_size, ut64 id, const char *output, ut8 *data, ut64 *written) {
	Ext2Geometry current;
	ExtJournal *j = history->journal;
	if (!ext2_geometry (j->root, &current) || current.block_size != j->block_size || current.inode_size != inode_size
			|| !ext2_inode_valid (&current, id, inode)) {
		R_LOG_ERROR ("Cannot validate the historical inode and current allocation layout");
		return false;
	}
	Ext2BitmapCache cache = {0};
	current.cache = &cache;
	history->current = &current;
	history->inode_id = id;
	history->generation = r_read_le32 (inode + 100);
	history->eligible = !j->active && !(current.incompat & 4) && !r_read_le32 (inode + 20) && r_read_le16 (inode + 26);
	RFSRoot overlay = *j->root;
	overlay.iob.io = (RIO *)history;
	overlay.iob.read_at = ext_journal_history_read;
	Ext2Geometry historical = current;
	historical.root = &overlay;
	historical.cache = NULL;
	history->reading = true;
	ut64 size = ext2_size (inode);
	ExtJournalRecovery recovery = { .fs = fs, .geometry = &historical, .output = output, .data = data };
	bool inline_link = ext2_inline_link (&historical, inode);
	recovery.sparse_known = inline_link || ext2_sparse_known (&historical, inode, id);
	bool ok = !strcmp (output, "-") || r_file_dump (output, NULL, 0, false);
	if (ok && inline_link) {
		ok = !strcmp (output, "-")? fs->csb.cb_write (fs->csb.cons, (const char *)inode + 40, size): r_file_dump (output, inode + 40, size, true);
		recovery.written = ok? size: 0;
	} else if (ok) {
		ok = ext2_walk_inode (&historical, inode, id, size, ext_journal_recover_block, &recovery) == R_FS_WALK_COMPLETE;
	}
	*written = recovery.written;
	history->current = NULL;
	free (cache.data);
	r_bitset_free (cache.metadata);
	return ok && *written == size;
}

static bool ext_journal_recover(RFS *fs, ExtJournal *j, ut32 sequence, ut64 id, const char *output, bool free_space) {
	ExtJournalHistory history = { .journal = j, .sequence = sequence };
	history.versions = ht_up_new (NULL, ext_journal_version_free, NULL);
	history.data = malloc (j->block_size);
	history.later = free_space? r_bitset_new (): NULL;
	ut8 *inode = NULL, *data = NULL;
	GrubFS *file = NULL;
	ut64 written = 0, size = 0;
	bool ok = false, opened = false;
	if (!history.versions || !history.data || (free_space && !history.later)) {
		goto done;
	}
	if (!ext_journal_scan (j, ext_journal_version, &history) || history.failed || !history.selected) {
		R_LOG_ERROR ("Cannot establish the requested committed journal transaction");
		goto done;
	}
	ut64 block;
	ut32 skip, inode_size;
	if (!ext_journal_inode_location (j, id, &skip, &inode_size, &block)) {
		goto done;
	}
	ExtJournalVersion *version = ht_up_find (history.versions, block, NULL);
	if (!version || !ext_journal_payload (j, &version->tag, history.data)) {
		R_LOG_ERROR ("No retained inode version at this transaction");
		goto done;
	}
	inode = malloc (inode_size);
	data = malloc (j->block_size);
	if (!inode || !data) {
		goto done;
	}
	memcpy (inode, history.data + skip, inode_size);
	size = ext2_size (inode);
	ut16 mode = r_read_le16 (inode) & 0xf000;
	if ((mode != 0x8000 && mode != 0xa000) || (r_read_le32 (inode + 32) & (0x10000000 | 4))) {
		R_LOG_ERROR ("Journal file recovery requires a regular file or symlink inode");
		goto done;
	}
	if (free_space) {
		ok = ext_journal_recover_free (fs, &history, inode, inode_size, id, output, data, &written);
		goto done;
	}
	bool standard_output = !strcmp (output, "-");
	if (!standard_output && !r_file_dump (output, NULL, 0, false)) {
		goto done;
	}
	if (mode == 0xa000 && size <= 60 && r_read_le32 (inode + 28) <= (r_read_le32 (inode + 104)? j->block_size / 512: 0)) {
		if (standard_output) {
			ok = fs->csb.cb_write (fs->csb.cons, (const char *)inode + 40, size);
		} else {
			ok = r_file_dump (output, inode + 40, size, false);
		}
		written = ok? size: 0;
		goto done;
	}
	RIOBind binding = { .init = 1, .io = (RIO *)&history, .read_at = ext_journal_history_read };
	file = grubfs_new (&grub_ext2_fs, &binding);
	if (!file) {
		goto done;
	}
	grubfs_bind_io (NULL, j->root->delta);
	if (grub_ext2_open_inode (file->file, id, inode)) {
		goto done;
	}
	opened = true;
	history.reading = true;
	while (written < size && (!fs->csb.is_breaked || !fs->csb.is_breaked (fs->csb.cons))) {
		int chunk = R_MIN ((ut64)j->block_size, size - written);
		grubfs_bind_io (NULL, j->root->delta);
		file->file->offset = written;
		int nread = file->file->fs->read (file->file, (char *)data, chunk);
		if (nread < 1 || nread > chunk) {
			break;
		}
		if (standard_output) {
			if (!fs->csb.cb_write (fs->csb.cons, (const char *)data, nread)) {
				break;
			}
		} else if (!r_file_dump (output, data, nread, true)) {
			break;
		}
		written += nread;
	}
	ok = written == size;
 done:
	if (!ok) {
		R_LOG_WARN ("Partial journal recovery: %"PFMT64u" of %"PFMT64u" bytes; %s", written, size,
			free_space? "missing, reused or unverifiable blocks stop recovery": "missing blocks are not read from the current image");
	}
	if (history.used_current) {
		R_LOG_WARN ("Heuristic recovery uses current free-space bytes; their original contents cannot be verified");
	}
	if (opened) {
		file->file->fs->close (file->file);
	}
	grubfs_free (file);
	ht_up_free (history.versions);
	r_bitset_free (history.owners);
	r_bitset_free (history.later);
	free (history.data);
	free (inode);
	free (data);
	return ok;
}

typedef struct ext_journal_name_t ExtJournalName;

typedef struct {
	ut32 id, sequence;
	ut8 inode[128];
	ExtJournalName *parent;
	char *path;
	unsigned state;
	bool ambiguous;
} ExtJournalNamedInode;

struct ext_journal_name_t {
	ExtJournalNamedInode *directory;
	ut32 id, sequence;
	ut64 block;
	char *name;
	bool deleted, conflict;
};

typedef struct {
	ExtJournalHistory *history;
	Ext2Geometry *geometry;
	ExtJournalTable *tables;
	ut32 table_count;
	HtUP *nodes, *blocks;
	HtPP *unique;
	RList *inodes, *names;
	ExtJournalNamedInode *directory;
	ut64 block;
	ut32 block_sequence, walked;
	ut8 *data;
	bool failed, partial;
} ExtJournalNames;

static void ext_journal_named_inode_free(void *ptr) {
	ExtJournalNamedInode *node = ptr;
	free (node->path);
	free (node);
}

static void ext_journal_name_free(void *ptr) {
	ExtJournalName *entry = ptr;
	free (entry->name);
	free (entry);
}

static int ext_journal_named_inode_compare(const void *a, const void *b) {
	const ExtJournalNamedInode *left = a, *right = b;
	return left->id < right->id? -1: left->id > right->id;
}

static bool ext_journal_name_inodes(void *user, const ut64 block, const void *value) {
	ExtJournalNames *names = user;
	const ExtJournalVersion *version = value;
	ExtJournalTable *table = ext_journal_table_find (names->tables, names->table_count, block);
	if (!table || version->tag.revoked) {
		return true;
	}
	if (!ext_journal_payload (names->history->journal, &version->tag, names->data)) {
		names->failed = true;
		return false;
	}
	Ext2Geometry *g = names->geometry;
	ut64 id = table->inode + (block - table->first) * (g->block_size / g->inode_size);
	ut32 offset;
	for (offset = 0; offset < g->block_size && id < table->inode_end; offset += g->inode_size, id++) {
		ut8 *inode = names->data + offset;
		ut16 mode = r_read_le16 (inode) & 0xf000;
		if (mode != 0x8000 && mode != 0x4000 && mode != 0xa000
				&& mode != 0x1000 && mode != 0x2000 && mode != 0x6000 && mode != 0xc000) {
			continue;
		}
		if (!ext2_inode_valid (g, id, inode)) {
			names->partial = true;
			continue;
		}
		if (r_list_length (names->inodes) >= EXT_JOURNAL_LIMIT) {
			names->failed = true;
			return false;
		}
		ExtJournalNamedInode *node = R_NEW0 (ExtJournalNamedInode);
		node->id = id;
		node->sequence = version->sequence;
		memcpy (node->inode, inode, sizeof (node->inode));
		if (!r_list_append (names->inodes, node)) {
			free (node);
			names->failed = true;
			return false;
		}
		if (!ht_up_insert (names->nodes, id, node)) {
			names->failed = true;
			return false;
		}
	}
	return true;
}

static bool ext_journal_name_entry(ut32 id, const char *name, bool deleted, void *user) {
	ExtJournalNames *names = user;
	if (!strcmp (name, ".") || !strcmp (name, "..")) {
		return true;
	}
	if (r_list_length (names->names) >= EXT_JOURNAL_LIMIT) {
		names->failed = true;
		return false;
	}
	ExtJournalName *entry = R_NEW0 (ExtJournalName);
	entry->directory = names->directory;
	entry->id = id;
	entry->sequence = names->block_sequence;
	entry->block = names->block;
	entry->deleted = deleted;
	entry->name = strdup (name);
	if (!entry->name || !r_list_append (names->names, entry)) {
		ext_journal_name_free (entry);
		names->failed = true;
		return false;
	}
	if (!deleted) {
		char *key = r_str_newf ("%u/%s", entry->directory->id, name);
		ExtJournalName *previous = key? ht_pp_find (names->unique, key, NULL): NULL;
		if (previous) {
			previous->conflict = entry->conflict = true;
		} else if (!key || !ht_pp_insert (names->unique, key, entry)) {
			names->failed = true;
		}
		free (key);
	}
	return !names->failed;
}

static int ext_journal_name_block(ut64 block, ut64 logical, ut64 size, unsigned depth, ut32 flags, void *user) {
	ExtJournalNames *names = user;
	ExtJournal *j = names->history->journal;
	if (names->walked++ >= EXT_JOURNAL_LIMIT || (j->console && j->console->is_breaked && j->console->is_breaked (j->console->cons))) {
		names->failed = true;
		return R_FS_WALK_STOPPED;
	}
	if (depth) {
		return R_FS_WALK_COMPLETE;
	}
	ExtJournalVersion *version = ht_up_find (names->history->versions, block, NULL);
	if (!block || (flags & R_FS_RANGE_UNWRITTEN) || size != j->block_size || !version || version->tag.revoked) {
		names->partial = true;
		return R_FS_WALK_COMPLETE;
	}
	if (!ext_journal_payload (j, &version->tag, names->data)) {
		names->failed = true;
		return R_FS_WALK_ERROR;
	}
	ExtJournalNamedInode *owner = ht_up_find (names->blocks, block, NULL);
	if (owner) {
		owner->ambiguous = names->directory->ambiguous = true;
		names->partial = true;
		return R_FS_WALK_COMPLETE;
	}
	if (!ht_up_insert (names->blocks, block, names->directory)) {
		names->failed = true;
		return R_FS_WALK_ERROR;
	}
	names->block = block;
	names->block_sequence = version->sequence;
	int status = ext2_directory_block (names->geometry, names->directory->inode, names->directory->id,
		names->data, size, logical, ext_journal_name_entry, names, true, true);
	names->partial |= status != R_FS_WALK_COMPLETE;
	return names->failed? R_FS_WALK_ERROR: R_FS_WALK_COMPLETE;
}

static ExtJournalNamedInode *ext_journal_name_match(ExtJournalNames *names, ExtJournalName *entry) {
	ExtJournalNamedInode *node = ht_up_find (names->nodes, entry->id, NULL);
	return node && !entry->deleted && !entry->conflict && !entry->directory->ambiguous && !r_read_le32 (node->inode + 20)
		&& r_read_le16 (node->inode + 26) && entry->sequence - node->sequence <= INT_MAX? node: NULL;
}

static const char *ext_journal_name_path(ExtJournalNamedInode *node, unsigned depth) {
	if (node->state || depth >= 128) {
		return node->state == 2? node->path: NULL;
	}
	node->state = 1;
	if ((r_read_le16 (node->inode) & 0xf000) == 0x4000 && !r_read_le32 (node->inode + 20)
			&& r_read_le16 (node->inode + 26) && !node->ambiguous) {
		if (node->id == 2) {
			node->path = strdup ("/");
		} else if (node->parent) {
			const char *parent = ext_journal_name_path (node->parent->directory, depth + 1);
			if (parent && strlen (parent) + strlen (node->parent->name) + 2 <= 4096) {
				node->path = r_str_newf ("%s%s%s", parent, !strcmp (parent, "/")? "": "/", node->parent->name);
			}
		}
	}
	node->state = node->path? 2: 3;
	return node->path;
}

static void ext_journal_names(RFS *fs, ExtJournal *j, ut32 sequence, ut64 filter, bool json) {
	Ext2Geometry geometry;
	if (!ext2_geometry (j->root, &geometry) || geometry.block_size != j->block_size || geometry.blocks != j->blocks) {
		R_LOG_ERROR ("Cannot establish the historical directory layout");
		return;
	}
	ExtJournalHistory history = { .journal = j, .sequence = sequence };
	history.versions = ht_up_new (NULL, ext_journal_version_free, NULL);
	history.data = malloc (j->block_size);
	ExtJournalNames names = { .history = &history, .geometry = &geometry };
	names.nodes = ht_up_new0 ();
	names.blocks = ht_up_new0 ();
	names.unique = ht_pp_new0 ();
	names.inodes = r_list_newf (ext_journal_named_inode_free);
	names.names = r_list_newf (ext_journal_name_free);
	names.data = malloc (j->block_size);
	ut32 inode_size;
	names.tables = ext_journal_tables (j, &names.table_count, &inode_size);
	if (!history.versions || !history.data || !names.nodes || !names.blocks || !names.unique || !names.inodes || !names.names || !names.data
			|| !names.tables || inode_size != geometry.inode_size) {
		names.failed = true;
		goto done;
	}
	ut32 i;
	for (i = 0; i < names.table_count; i++) {
		ut8 desc[64];
		if (!ext2_group (&geometry, (names.tables[i].inode - 1) / geometry.inodes_per_group, desc)
				|| ext2_group_block (&geometry, desc, 8) != names.tables[i].first) {
			names.failed = true;
			goto done;
		}
	}
	if (!ext_journal_scan (j, ext_journal_version, &history) || history.failed || !history.selected) {
		R_LOG_ERROR ("Cannot establish the requested committed journal transaction");
		names.failed = true;
		goto done;
	}
	ht_up_foreach (history.versions, ext_journal_name_inodes, &names);
	r_list_sort (names.inodes, ext_journal_named_inode_compare);
	RFSRoot overlay = *j->root;
	overlay.iob.io = (RIO *)&history;
	overlay.iob.read_at = ext_journal_history_read;
	geometry.root = &overlay;
	history.reading = true;
	RListIter *iter;
	ExtJournalNamedInode *node;
	r_list_foreach (names.inodes, iter, node) {
		if (names.failed) {
			break;
		}
		if ((r_read_le16 (node->inode) & 0xf000) == 0x4000) {
			names.directory = node;
			int status = ext2_walk_inode (&geometry, node->inode, node->id, ext2_size (node->inode), ext_journal_name_block, &names);
			names.partial |= status != R_FS_WALK_COMPLETE;
		}
	}
	ExtJournalName *entry;
	r_list_foreach (names.names, iter, entry) {
		node = ext_journal_name_match (&names, entry);
		if (node && (r_read_le16 (node->inode) & 0xf000) == 0x4000) {
			if (node->id == 2 || node->parent) {
				node->ambiguous = true;
				entry->conflict = true;
				if (node->parent) {
					node->parent->conflict = true;
				}
			} else {
				node->parent = entry;
			}
		}
	}
	PJ *pj = json? pj_new (): NULL;
	if (pj) {
		pj_a (pj);
	}
	r_list_foreach (names.names, iter, entry) {
		if (filter != UT64_MAX && entry->id != filter) {
			continue;
		}
		entry->conflict |= entry->directory->ambiguous;
		const char *parent = ext_journal_name_path (entry->directory, 0);
		char *path = parent && !entry->conflict && strlen (parent) + strlen (entry->name) + 2 <= 4096?
			r_str_newf ("%s%s%s", parent, !strcmp (parent, "/")? "": "/", entry->name): NULL;
		node = ext_journal_name_match (&names, entry);
		if (pj) {
			pj_o (pj);
			pj_kn (pj, "sequence", sequence);
			pj_kn (pj, "directory", entry->directory->id);
			pj_kn (pj, "directory_sequence", entry->directory->sequence);
			pj_kn (pj, "block", entry->block);
			pj_kn (pj, "block_sequence", entry->sequence);
			pj_kn (pj, "inode", entry->id);
			pj_ks (pj, "name", entry->name);
			if (path) {
				pj_ks (pj, "path", path);
			} else {
				pj_knull (pj, "path");
			}
			if (node) {
				pj_kn (pj, "inode_sequence", node->sequence);
				pj_kn (pj, "generation", r_read_le32 (node->inode + 100));
			} else {
				pj_knull (pj, "inode_sequence");
				pj_knull (pj, "generation");
			}
			pj_kb (pj, "deleted", entry->deleted);
			pj_kb (pj, "conflict", entry->conflict);
			pj_kb (pj, "heuristic", true);
			pj_end (pj);
		} else {
			char *escaped = r_str_escape_utf8_keep_printable (path? path: entry->name, false, true);
			if (escaped) {
				fs->csb.cb_printf (fs->csb.cons, "%u %u %u %s %s\n", sequence, entry->directory->id, entry->id,
					entry->conflict? "conflict": entry->deleted? "slack": "entry", escaped);
				free (escaped);
			}
		}
		free (path);
	}
	if (pj) {
		pj_end (pj);
		fs->csb.cb_printf (fs->csb.cons, "%s\n", pj_string (pj));
		pj_free (pj);
	}
 done:
	if (names.failed || names.partial) {
		R_LOG_WARN ("Incomplete historical directory evidence: retaining recovered names and unresolved paths");
	}
	free (names.tables);
	free (names.data);
	ht_pp_free (names.unique);
	ht_up_free (names.nodes);
	ht_up_free (names.blocks);
	r_list_free (names.names);
	r_list_free (names.inodes);
	free (history.data);
	ht_up_free (history.versions);
}

static bool ext_journal_command(RFS *fs, const char *cmd) {
	if (strncmp (cmd, "ext2", 4) || (cmd[4] && cmd[4] != '?' && !IS_WHITECHAR (cmd[4]))) {
		return false;
	}
	if (!fs->csb.cb_printf || !fs->csb.cb_write) {
		R_LOG_ERROR ("Journal commands require a console binding");
		return true;
	}
	int argc = 0;
	char **argv = r_str_argv (cmd, &argc);
	if (!argv) {
		return true;
	}
	bool inodes = argc > 1 && (!strcmp (argv[1], "journal-inodes") || !strcmp (argv[1], "journal-inodesj"));
	bool names = argc > 1 && (!strcmp (argv[1], "journal-names") || !strcmp (argv[1], "journal-namesj"));
	bool recover = argc > 1 && !strcmp (argv[1], "journal-recover");
	bool free_space = recover && argc == 7 && !strcmp (argv[6], "free");
	bool inode = recover || (argc > 1 && (!strcmp (argv[1], "journal-inode") || !strcmp (argv[1], "journal-inodej")));
	bool json = argc > 1 && (!strcmp (argv[1], "journalj") || !strcmp (argv[1], "journal-inodej") || !strcmp (argv[1], "journal-inodesj") || !strcmp (argv[1], "journal-namesj"));
	if (argc < 3 || (strcmp (argv[1], "journal") && !json && !inode && !inodes && !names)
			|| (recover && argc != 6 && argc != 7) || (recover && argc == 7 && !free_space && strcmp (argv[6], "journal"))
			|| (names && argc != 4 && argc != 5)
			|| (!recover && !names && (inodes? (argc != 3 && argc != 4): inode? (argc != 5 && argc != 6): (argc != 3 && argc != 6)))) {
		fs->csb.cb_printf (fs->csb.cons, "Usage: m:ext2 journal[j] /mount [sequence block output|-]\n"
			"       m:ext2 journal-inodes[j] /mount [sequence]\n"
			"       m:ext2 journal-inode[j] /mount sequence inode [output|-]\n"
			"       m:ext2 journal-names[j] /mount sequence [inode]\n"
			"       m:ext2 journal-recover /mount sequence inode output|- [journal|free]\n"
			"List committed journal versions or recover journal-resident blocks, inodes, and file data.\n"
			"Recovery defaults to journal bytes; free mode also reads unowned free blocks when the inode generation matches.\n"
			"Current free-space bytes are heuristic; retained later writes and revocations exclude them.\n"
			"Free-space fallback requires allocation metadata that does not need journal replay.\n"
			"Names use retained directory evidence only; missing or ambiguous ancestors leave paths unresolved.\n"
			"Historical names and paths are heuristic; JSON includes block and inode-version provenance.\n"
			"Checkpointed transactions are scanned; incomplete or corrupt transactions are skipped.\n");
		r_str_argv_free (argv);
		return true;
	}
	RListIter *iter;
	RFSRoot *root, *mounted = NULL;
	r_list_foreach (fs->roots, iter, root) {
		if (!strcmp (root->path, argv[2]) && !strcmp (root->p->meta.name, "ext2")) {
			mounted = root;
			break;
		}
	}
	ExtJournalOutput output = { .fs = fs, .extract = inode || argc == 6, .inodes = inodes, .filter_sequence = names || (inodes && argc == 4) };
	if (output.extract || output.filter_sequence) {
		const char *error = NULL;
		RNum number = {0};
		ut64 sequence = r_num_math_err (&number, argv[3], &error);
		if (!*r_str_trim_head_ro (argv[3]) || error || number.dbz || sequence > UT32_MAX) {
			R_LOG_ERROR ("Invalid journal sequence");
			goto done;
		}
		output.sequence = sequence;
		bool have_id = output.extract || (names && argc == 5);
		output.block = have_id? r_num_math_err (&number, argv[4], &error): 0;
		if (have_id && (!*r_str_trim_head_ro (argv[4]) || error || number.dbz || (names && (!output.block || output.block > UT32_MAX)))) {
			R_LOG_ERROR ("Invalid filesystem block number");
			goto done;
		}
	}
	if (!mounted) {
		R_LOG_ERROR ("An ext2/ext3/ext4 mountpoint is required");
		goto done;
	}
	ExtJournal journal;
	if (!ext_journal_open (mounted, &journal)) {
		R_LOG_ERROR ("Cannot read the filesystem journal");
		goto done;
	}
	journal.console = &fs->csb;
	if (names) {
		ext_journal_names (fs, &journal, output.sequence, argc == 5? output.block: UT64_MAX, json);
		ext_journal_close (&journal);
		goto done;
	}
	if (output.extract && !inode && output.block >= journal.blocks) {
		R_LOG_ERROR ("Filesystem block number is out of range");
		ext_journal_close (&journal);
		goto done;
	}
	ut64 inode_id = output.block;
	if (recover) {
		ext_journal_recover (fs, &journal, output.sequence, inode_id, argv[5], free_space);
		ext_journal_close (&journal);
		goto done;
	}
	ut32 skip = 0, size = journal.block_size;
	if (inode && !ext_journal_inode_location (&journal, inode_id, &skip, &size, &output.block)) {
		R_LOG_ERROR ("Cannot locate the inode table for this inode");
		ext_journal_close (&journal);
		goto done;
	}
	if (inodes) {
		output.tables = ext_journal_tables (&journal, &output.table_count, &output.inode_size);
		if (!output.tables) {
			R_LOG_ERROR ("Cannot establish the inode-table layout");
			ext_journal_close (&journal);
			goto done;
		}
	}
	output.json = json && !output.extract? pj_new (): NULL;
	if (output.json) {
		pj_a (output.json);
	}
	if (output.extract || inodes) {
		output.data = malloc (journal.block_size);
	}
	if ((!output.extract && !inodes) || output.data) {
		bool ok = ext_journal_scan (&journal, ext_journal_record, &output);
		if (!ok) {
			R_LOG_WARN ("Journal scan stopped before the end");
		}
		if (output.extract) {
			if (!output.found || output.failed) {
				R_LOG_ERROR ("No unrevoked committed version of this block was recovered");
			} else if (inode && argc == 5) {
				ext_journal_inode_info (fs, output.data + skip, inode_id, output.sequence, json);
			} else if (!strcmp (argv[5], "-")) {
				fs->csb.cb_write (fs->csb.cons, (const char *)output.data + skip, size);
			} else if (!r_file_dump (argv[5], output.data + skip, size, false)) {
				R_LOG_ERROR ("Cannot write recovered journal block");
			}
		}
	}
	if (output.json) {
		pj_end (output.json);
		fs->csb.cb_printf (fs->csb.cons, "%s\n", pj_string (output.json));
	}
	pj_free (output.json);
	free (output.tables);
	free (output.data);
	ext_journal_close (&journal);
 done:
	r_str_argv_free (argv);
	return true;
}

static bool ext_journal_mount(RFSRoot *root) {
	if (FSP(_forensic_mount) (root)) {
		return true;
	}
	ut8 super[256];
	if (root->delta > UT64_MAX - 1280 || root->iob.read_at (root->iob.io, root->delta + 1024, super, sizeof (super)) != sizeof (super)
			|| r_read_le16 (super + 56) != 0xef53 || !(r_read_le32 (super + 92) & 4)) {
		return false;
	}
	ExtJournal journal;
	if (!ext_journal_open (root, &journal)) {
		return false;
	}
	ext_journal_close (&journal);
	R_LOG_WARN ("Damaged ext3/ext4 directory metadata: enabling journal inspection");
	return true;
}
