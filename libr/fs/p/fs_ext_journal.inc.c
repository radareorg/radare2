/* radare - LGPL - Copyright 2026 - pancake */

#include <r_hash.h>

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
} ExtJournal;

typedef bool (*ExtJournalCb)(ExtJournal *journal, ut32 sequence, ut32 start, const ExtJournalTag *tag, void *user);

static ut32 ext_journal_crc(const ut8 *data, ut32 size) {
	return ~(ut32)r_hash_crc_preset (data, size, CRC_PRESET_32C);
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
		ut32 low = 0, high = out->table_count;
		while (low < high) {
			ut32 mid = low + (high - low) / 2;
			if (out->tables[mid].end <= tag->block) {
				low = mid + 1;
			} else {
				high = mid;
			}
		}
		if (low >= out->table_count || out->tables[low].first > tag->block) {
			return true;
		}
		if (!ext_journal_payload (j, tag, out->data)) {
			out->failed = true;
			return false;
		}
		ut64 id = out->tables[low].inode + (tag->block - out->tables[low].first) * (j->block_size / out->inode_size);
		ut32 offset;
		for (offset = 0; offset < j->block_size && id < out->tables[low].inode_end; offset += out->inode_size, id++) {
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
} ExtJournalHistory;

static void ext_journal_version_free(HtUPKv *kv) {
	free (kv->value);
}

static bool ext_journal_version(ExtJournal *j, ut32 sequence, ut32 start, const ExtJournalTag *tag, void *user) {
	ExtJournalHistory *history = user;
	ut32 age = history->sequence - sequence;
	if (age > INT_MAX) {
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
		if (!version || !ext_journal_payload (j, &version->tag, history->data)) {
			return -1;
		}
		int chunk = R_MIN (len - done, j->block_size - offset);
		memcpy (buf + done, history->data + offset, chunk);
		done += chunk;
		relative += chunk;
	}
	return done;
}

static bool ext_journal_recover(RFS *fs, ExtJournal *j, ut32 sequence, ut64 id, const char *output) {
	ExtJournalHistory history = { .journal = j, .sequence = sequence };
	history.versions = ht_up_new (NULL, ext_journal_version_free, NULL);
	history.data = malloc (j->block_size);
	ut8 *inode = NULL, *data = NULL;
	GrubFS *file = NULL;
	ut64 written = 0, size = 0;
	bool ok = false, opened = false;
	if (!history.versions || !history.data) {
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
		R_LOG_WARN ("Partial journal recovery: %"PFMT64u" of %"PFMT64u" bytes; missing blocks are not read from the current image", written, size);
	}
	if (opened) {
		file->file->fs->close (file->file);
	}
	grubfs_free (file);
	ht_up_free (history.versions);
	free (history.data);
	free (inode);
	free (data);
	return ok;
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
	bool recover = argc > 1 && !strcmp (argv[1], "journal-recover");
	bool inode = recover || (argc > 1 && (!strcmp (argv[1], "journal-inode") || !strcmp (argv[1], "journal-inodej")));
	bool json = argc > 1 && (!strcmp (argv[1], "journalj") || !strcmp (argv[1], "journal-inodej") || !strcmp (argv[1], "journal-inodesj"));
	if (argc < 3 || (strcmp (argv[1], "journal") && !json && !inode && !inodes)
			|| (recover && argc != 6) || (inodes? (argc != 3 && argc != 4): inode? (argc != 5 && argc != 6): (argc != 3 && argc != 6))) {
		fs->csb.cb_printf (fs->csb.cons, "Usage: m:ext2 journal[j] /mount [sequence block output|-]\n"
			"       m:ext2 journal-inodes[j] /mount [sequence]\n"
			"       m:ext2 journal-inode[j] /mount sequence inode [output|-]\n"
			"       m:ext2 journal-recover /mount sequence inode output|-\n"
			"List committed journal versions or recover journal-resident blocks, inodes, and file data.\n"
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
	ExtJournalOutput output = { .fs = fs, .extract = inode || argc == 6, .inodes = inodes, .filter_sequence = inodes && argc == 4 };
	if (output.extract || output.filter_sequence) {
		const char *error = NULL;
		RNum number = {0};
		ut64 sequence = r_num_math_err (&number, argv[3], &error);
		if (!*r_str_trim_head_ro (argv[3]) || error || number.dbz || sequence > UT32_MAX) {
			R_LOG_ERROR ("Invalid journal sequence");
			goto done;
		}
		output.sequence = sequence;
		output.block = output.extract? r_num_math_err (&number, argv[4], &error): 0;
		if (output.extract && (!*r_str_trim_head_ro (argv[4]) || error || number.dbz)) {
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
	if (output.extract && !inode && output.block >= journal.blocks) {
		R_LOG_ERROR ("Filesystem block number is out of range");
		ext_journal_close (&journal);
		goto done;
	}
	ut64 inode_id = output.block;
	if (recover) {
		ext_journal_recover (fs, &journal, output.sequence, inode_id, argv[5]);
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
