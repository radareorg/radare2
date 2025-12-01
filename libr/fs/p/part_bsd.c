/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_fs.h>
#include <r_types.h>
#include <r_util.h>

#define BSD_DISKMAGIC ((ut32)0x82564557)
#define BSD_MAXPARTITIONS 16

R_PACKED(
typedef struct {
	ut32 p_size;    /* number of sectors in partition */
	ut32 p_offset;  /* starting sector */
	ut32 p_fsize;   /* filesystem basic fragment size */
	ut8  p_fstype;  /* filesystem type */
	ut8  p_frag;    /* filesystem fragments per block */
	ut16 p_cpg;     /* cylinders per group */
})
BSDPartition;

R_PACKED(
typedef struct {
	ut32 d_magic;           /* the magic number */
	ut16 d_type;            /* drive type */
	ut16 d_subtype;         /* controller/d_type specific */
	char d_typename[16];    /* type name */
	char d_packname[16];    /* pack identifier */
	ut32 d_secsize;         /* # of bytes per sector */
	ut32 d_nsectors;        /* # of data sectors per track */
	ut32 d_ntracks;         /* # of tracks per cylinder */
	ut32 d_ncylinders;      /* # of data cylinders per unit */
	ut32 d_secpercyl;       /* # of data sectors per cylinder */
	ut32 d_secperunit;      /* # of data sectors per unit */
	ut16 d_sparespertrack;  /* # of spare sectors per track */
	ut16 d_sparespercyl;    /* # of spare sectors per cylinder */
	ut32 d_acylinders;      /* # of alt. cylinders per unit */
	ut16 d_rpm;             /* rotational speed */
	ut16 d_interleave;      /* hardware sector interleave */
	ut16 d_trackskew;       /* sector 0 skew, per track */
	ut16 d_cylskew;         /* sector 0 skew, per cylinder */
	ut32 d_headswitch;      /* head switch time, usec */
	ut32 d_trkseek;         /* track-to-track seek, usec */
	ut32 d_flags;           /* generic flags */
	ut32 d_drivedata[5];    /* drive-type specific information */
	ut32 d_spare[5];        /* reserved for future use */
	ut32 d_magic2;          /* the magic number (again) */
	ut16 d_checksum;        /* xor of data incl. partitions */
	ut16 d_npartitions;     /* number of partitions in following */
	ut32 d_bbsize;          /* size of boot area at sn0, bytes */
	ut32 d_sbsize;          /* max size of fs superblock, bytes */
	BSDPartition d_partitions[BSD_MAXPARTITIONS]; /* the partition table */
})
BSDDiskLabel;

static int fs_part_bsd(void *disk, void *ptr, void *closure) {
	RFS *fs = (RFS *)disk;
	RFSPartitionIterator iterate = (RFSPartitionIterator)ptr;
	RList *list = (RList *)closure;

	BSDDiskLabel label;

	// Read BSD disklabel at sector 1 (offset 512)
	if (!fs->iob.read_at (fs->iob.io, 512, (ut8 *)&label, sizeof (label))) {
		R_LOG_ERROR ("Failed to read BSD disklabel");
		return 0;
	}

	// BSD disklabel is little-endian, so read fields with endian conversion
	ut32 d_magic = r_read_ble32 ((ut8 *)&label.d_magic, false);
	ut32 d_magic2 = r_read_ble32 ((ut8 *)&label.d_magic2, false);
	ut16 d_npartitions = r_read_ble16 ((ut8 *)&label.d_npartitions, false);
	ut32 d_secsize = r_read_ble32 ((ut8 *)&label.d_secsize, false);

	// Check magic numbers
	if (d_magic != BSD_DISKMAGIC || d_magic2 != BSD_DISKMAGIC) {
		R_LOG_ERROR ("Invalid BSD disklabel magic");
		return 0;
	}

	// Validate number of partitions
	if (d_npartitions == 0 || d_npartitions > BSD_MAXPARTITIONS) {
		R_LOG_ERROR ("Invalid number of BSD partitions: %u", d_npartitions);
		return 0;
	}

	int i;
	for (i = 0; i < d_npartitions; i++) {
		BSDPartition *p = &label.d_partitions[i];

		// Read partition fields with endian conversion
		ut32 p_size = r_read_ble32 ((ut8 *)&p->p_size, false);
		ut32 p_offset = r_read_ble32 ((ut8 *)&p->p_offset, false);
		ut8 p_fstype = p->p_fstype; // ut8, no conversion needed

		// Skip unused partitions
		if (p_fstype == 0 || p_size == 0) {
			continue;
		}

		// Calculate start and size in bytes, cast to ut64 to prevent overflow
		ut64 start = (ut64)p_offset * (ut64)d_secsize;
		ut64 size = (ut64)p_size * (ut64)d_secsize;

		// Check for overflow in multiplication
		if (p_offset != 0 && start / p_offset != d_secsize) {
			R_LOG_ERROR ("Integer overflow in partition start calculation for partition %d", i);
			continue;
		}
		if (p_size != 0 && size / p_size != d_secsize) {
			R_LOG_ERROR ("Integer overflow in partition size calculation for partition %d", i);
			continue;
		}

		RFSPartition *par = r_fs_partition_new (i, start, size);
		par->type = p_fstype;

		iterate (fs, par, list);
	}

	return 0;
}
