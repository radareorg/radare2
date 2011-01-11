/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2009,2010  Free Software Foundation, Inc.
 *  Copyright 2010  Sun Microsystems, Inc.
 *
 *  GRUB is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * The zfs plug-in routines for GRUB are:
 *
 * zfs_mount() - locates a valid uberblock of the root pool and reads
 *		in its MOS at the memory address MOS.
 *
 * zfs_open() - locates a plain file object by following the MOS
 *		and places its dnode at the memory address DNODE.
 *
 * zfs_read() - read in the data blocks pointed by the DNODE.
 *
 */

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/partition.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/zfs/zfs.h>
#include <grub/zfs/zio.h>
#include <grub/zfs/dnode.h>
#include <grub/zfs/uberblock_impl.h>
#include <grub/zfs/vdev_impl.h>
#include <grub/zfs/zio_checksum.h>
#include <grub/zfs/zap_impl.h>
#include <grub/zfs/zap_leaf.h>
#include <grub/zfs/zfs_znode.h>
#include <grub/zfs/dmu.h>
#include <grub/zfs/dmu_objset.h>
#include <grub/zfs/sa_impl.h>
#include <grub/zfs/dsl_dir.h>
#include <grub/zfs/dsl_dataset.h>

#define	ZPOOL_PROP_BOOTFS		"bootfs"

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

/*
 * For nvlist manipulation. (from nvpair.h)
 */
#define	NV_ENCODE_NATIVE	0
#define	NV_ENCODE_XDR		1
#define	NV_BIG_ENDIAN	        0
#define	NV_LITTLE_ENDIAN	1
#define	DATA_TYPE_UINT64	8
#define	DATA_TYPE_STRING	9
#define	DATA_TYPE_NVLIST	19
#define	DATA_TYPE_NVLIST_ARRAY	20

#ifndef GRUB_UTIL
static grub_dl_t my_mod;
#endif

#define	P2PHASE(x, align)		((x) & ((align) - 1))
#define	DVA_OFFSET_TO_PHYS_SECTOR(offset) \
	((offset + VDEV_LABEL_START_SIZE) >> SPA_MINBLOCKSHIFT)

/*
 * FAT ZAP data structures
 */
#define	ZFS_CRC64_POLY 0xC96C5795D7870F42ULL	/* ECMA-182, reflected form */
#define	ZAP_HASH_IDX(hash, n)	(((n) == 0) ? 0 : ((hash) >> (64 - (n))))
#define	CHAIN_END	0xffff	/* end of the chunk chain */

/*
 * The amount of space within the chunk available for the array is:
 * chunk size - space for type (1) - space for next pointer (2)
 */
#define	ZAP_LEAF_ARRAY_BYTES (ZAP_LEAF_CHUNKSIZE - 3)

#define	ZAP_LEAF_HASH_SHIFT(bs)	(bs - 5)
#define	ZAP_LEAF_HASH_NUMENTRIES(bs) (1 << ZAP_LEAF_HASH_SHIFT(bs))
#define	LEAF_HASH(bs, h) \
	((ZAP_LEAF_HASH_NUMENTRIES(bs)-1) & \
	((h) >> (64 - ZAP_LEAF_HASH_SHIFT(bs)-l->l_hdr.lh_prefix_len)))

/*
 * The amount of space available for chunks is:
 * block size shift - hash entry size (2) * number of hash
 * entries - header space (2*chunksize)
 */
#define	ZAP_LEAF_NUMCHUNKS(bs) \
	(((1<<bs) - 2*ZAP_LEAF_HASH_NUMENTRIES(bs)) / \
	ZAP_LEAF_CHUNKSIZE - 2)

/*
 * The chunks start immediately after the hash table.  The end of the
 * hash table is at l_hash + HASH_NUMENTRIES, which we simply cast to a
 * chunk_t.
 */
#define	ZAP_LEAF_CHUNK(l, bs, idx) \
	((zap_leaf_chunk_t *)(l->l_hash + ZAP_LEAF_HASH_NUMENTRIES(bs)))[idx]
#define	ZAP_LEAF_ENTRY(l, bs, idx) (&ZAP_LEAF_CHUNK(l, bs, idx).l_entry)


/*
 * Decompression Entry - lzjb
 */
#ifndef	NBBY
#define	NBBY	8
#endif

extern grub_err_t lzjb_decompress (void *, void *, grub_size_t, grub_size_t);

typedef grub_err_t zfs_decomp_func_t (void *s_start, void *d_start,
				      grub_size_t s_len, grub_size_t d_len);
typedef struct decomp_entry
{
  char *name;
  zfs_decomp_func_t *decomp_func;
} decomp_entry_t;

typedef struct dnode_end
{
  dnode_phys_t dn;
  grub_zfs_endian_t endian;
} dnode_end_t;

struct grub_zfs_data
{
  /* cache for a file block of the currently zfs_open()-ed file */
  char *file_buf;
  grub_uint64_t file_start;
  grub_uint64_t file_end;

  /* cache for a dnode block */
  dnode_phys_t *dnode_buf;
  dnode_phys_t *dnode_mdn;
  grub_uint64_t dnode_start;
  grub_uint64_t dnode_end;
  grub_zfs_endian_t dnode_endian;

  uberblock_t current_uberblock;
  grub_disk_t disk;

  dnode_end_t mos;
  dnode_end_t mdn;
  dnode_end_t dnode;

  grub_disk_addr_t vdev_phys_sector;
};

decomp_entry_t decomp_table[ZIO_COMPRESS_FUNCTIONS] = {
  {"inherit", NULL},		/* ZIO_COMPRESS_INHERIT */
  {"on", lzjb_decompress},	/* ZIO_COMPRESS_ON */
  {"off", NULL},		/* ZIO_COMPRESS_OFF */
  {"lzjb", lzjb_decompress},	/* ZIO_COMPRESS_LZJB */
  {"empty", NULL},		/* ZIO_COMPRESS_EMPTY */
  {"gzip", NULL},		/* ZIO_COMPRESS_GZIP */
};

static grub_err_t zio_read_data (blkptr_t * bp, grub_zfs_endian_t endian,
				 void *buf, struct grub_zfs_data *data);

/*
 * Our own version of log2().  Same thing as highbit()-1.
 */
static int
zfs_log2 (grub_uint64_t num)
{
  int i = 0;

  while (num > 1)
    {
      i++;
      num = num >> 1;
    }

  return (i);
}

/* Checksum Functions */
static void
zio_checksum_off (const void *buf __attribute__ ((unused)),
		  grub_uint64_t size __attribute__ ((unused)),
		  grub_zfs_endian_t endian __attribute__ ((unused)),
		  zio_cksum_t * zcp)
{
  ZIO_SET_CHECKSUM (zcp, 0, 0, 0, 0);
}

/* Checksum Table and Values */
zio_checksum_info_t zio_checksum_table[ZIO_CHECKSUM_FUNCTIONS] = {
  {NULL, 0, 0, "inherit"},
  {NULL, 0, 0, "on"},
  {zio_checksum_off, 0, 0, "off"},
  {zio_checksum_SHA256, 1, 1, "label"},
  {zio_checksum_SHA256, 1, 1, "gang_header"},
  {NULL, 0, 0, "zilog"},
  {fletcher_2, 0, 0, "fletcher2"},
  {fletcher_4, 1, 0, "fletcher4"},
  {zio_checksum_SHA256, 1, 0, "SHA256"},
  {NULL, 0, 0, "zilog2"},
};

/*
 * zio_checksum_verify: Provides support for checksum verification.
 *
 * Fletcher2, Fletcher4, and SHA256 are supported.
 *
 */
static grub_err_t
zio_checksum_verify (zio_cksum_t zc, grub_uint32_t checksum,
		     grub_zfs_endian_t endian, char *buf, int size)
{
  zio_eck_t *zec = (zio_eck_t *) (buf + size) - 1;
  zio_checksum_info_t *ci = &zio_checksum_table[checksum];
  zio_cksum_t actual_cksum, expected_cksum;

  if (checksum >= ZIO_CHECKSUM_FUNCTIONS || ci->ci_func == NULL)
    {
      grub_dprintf ("zfs", "unknown checksum function %d\n", checksum);
      return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, 
			 "unknown checksum function %d", checksum);
    }

  if (ci->ci_eck)
    {
      expected_cksum = zec->zec_cksum;  
      zec->zec_cksum = zc;  
      ci->ci_func (buf, size, endian, &actual_cksum);
      zec->zec_cksum = expected_cksum;
      zc = expected_cksum;
    }
  else
    ci->ci_func (buf, size, endian, &actual_cksum);

  if ((actual_cksum.zc_word[0] != zc.zc_word[0]) 
      || (actual_cksum.zc_word[1] != zc.zc_word[1]) 
      || (actual_cksum.zc_word[2] != zc.zc_word[2]) 
      || (actual_cksum.zc_word[3] != zc.zc_word[3]))
    {
      grub_dprintf ("zfs", "checksum %d verification failed\n", checksum);
      grub_dprintf ("zfs", "actual checksum %16llx %16llx %16llx %16llx\n",
		    (unsigned long long) actual_cksum.zc_word[0], 
		    (unsigned long long) actual_cksum.zc_word[1],
		    (unsigned long long) actual_cksum.zc_word[2], 
		    (unsigned long long) actual_cksum.zc_word[3]);
      grub_dprintf ("zfs", "expected checksum %16llx %16llx %16llx %16llx\n",
		    (unsigned long long) zc.zc_word[0], 
		    (unsigned long long) zc.zc_word[1],
		    (unsigned long long) zc.zc_word[2], 
		    (unsigned long long) zc.zc_word[3]);
      return grub_error (GRUB_ERR_BAD_FS, "checksum verification failed");
    }

  return GRUB_ERR_NONE;
}

/*
 * vdev_uberblock_compare takes two uberblock structures and returns an integer
 * indicating the more recent of the two.
 * 	Return Value = 1 if ub2 is more recent
 * 	Return Value = -1 if ub1 is more recent
 * The most recent uberblock is determined using its transaction number and
 * timestamp.  The uberblock with the highest transaction number is
 * considered "newer".  If the transaction numbers of the two blocks match, the
 * timestamps are compared to determine the "newer" of the two.
 */
static int
vdev_uberblock_compare (uberblock_t * ub1, uberblock_t * ub2)
{
  grub_zfs_endian_t ub1_endian, ub2_endian;
  if (grub_zfs_to_cpu64 (ub1->ub_magic, LITTLE_ENDIAN) == UBERBLOCK_MAGIC)
    ub1_endian = LITTLE_ENDIAN;
  else
    ub1_endian = BIG_ENDIAN;
  if (grub_zfs_to_cpu64 (ub2->ub_magic, LITTLE_ENDIAN) == UBERBLOCK_MAGIC)
    ub2_endian = LITTLE_ENDIAN;
  else
    ub2_endian = BIG_ENDIAN;

  if (grub_zfs_to_cpu64 (ub1->ub_txg, ub1_endian) 
      < grub_zfs_to_cpu64 (ub2->ub_txg, ub2_endian))
    return (-1);
  if (grub_zfs_to_cpu64 (ub1->ub_txg, ub1_endian) 
      > grub_zfs_to_cpu64 (ub2->ub_txg, ub2_endian))
    return (1);

  if (grub_zfs_to_cpu64 (ub1->ub_timestamp, ub1_endian) 
      < grub_zfs_to_cpu64 (ub2->ub_timestamp, ub2_endian))
    return (-1);
  if (grub_zfs_to_cpu64 (ub1->ub_timestamp, ub1_endian) 
      > grub_zfs_to_cpu64 (ub2->ub_timestamp, ub2_endian))
    return (1);

  return (0);
}

/*
 * Three pieces of information are needed to verify an uberblock: the magic
 * number, the version number, and the checksum.
 *
 * Currently Implemented: version number, magic number
 * Need to Implement: checksum
 *
 */
static grub_err_t
uberblock_verify (uberblock_phys_t * ub, int offset)
{
  uberblock_t *uber = &ub->ubp_uberblock;
  grub_err_t err;
  grub_zfs_endian_t endian = UNKNOWN_ENDIAN;
  zio_cksum_t zc;

  if (grub_zfs_to_cpu64 (uber->ub_magic, LITTLE_ENDIAN) == UBERBLOCK_MAGIC
      && grub_zfs_to_cpu64 (uber->ub_version, LITTLE_ENDIAN) > 0 
      && grub_zfs_to_cpu64 (uber->ub_version, LITTLE_ENDIAN) <= SPA_VERSION)
    endian = LITTLE_ENDIAN;

  if (grub_zfs_to_cpu64 (uber->ub_magic, BIG_ENDIAN) == UBERBLOCK_MAGIC
      && grub_zfs_to_cpu64 (uber->ub_version, BIG_ENDIAN) > 0 
      && grub_zfs_to_cpu64 (uber->ub_version, BIG_ENDIAN) <= SPA_VERSION)
    endian = BIG_ENDIAN;

  if (endian == UNKNOWN_ENDIAN)
    return grub_error (GRUB_ERR_BAD_FS, "invalid uberblock magic");

  grub_memset (&zc, 0, sizeof (zc));

  zc.zc_word[0] = grub_cpu_to_zfs64 (offset, endian);
  err = zio_checksum_verify (zc, ZIO_CHECKSUM_LABEL, endian,
			     (char *) ub, UBERBLOCK_SIZE);

  return err;
}

/*
 * Find the best uberblock.
 * Return:
 *    Success - Pointer to the best uberblock.
 *    Failure - NULL
 */
static uberblock_phys_t *
find_bestub (uberblock_phys_t * ub_array, grub_disk_addr_t sector)
{
  uberblock_phys_t *ubbest = NULL;
  int i;
  grub_disk_addr_t offset;
  grub_err_t err = GRUB_ERR_NONE;

  for (i = 0; i < (VDEV_UBERBLOCK_RING >> VDEV_UBERBLOCK_SHIFT); i++)
    {
      offset = (sector << SPA_MINBLOCKSHIFT) + VDEV_PHYS_SIZE
	+ (i << VDEV_UBERBLOCK_SHIFT);

      err = uberblock_verify (&ub_array[i], offset);
      if (err)
	{
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}
      if (ubbest == NULL 
	  || vdev_uberblock_compare (&(ub_array[i].ubp_uberblock),
				     &(ubbest->ubp_uberblock)) > 0)
	ubbest = &ub_array[i];
    }
  if (!ubbest)
    grub_errno = err;

  return (ubbest);
}

static inline grub_size_t
get_psize (blkptr_t * bp, grub_zfs_endian_t endian)
{
  return ((((grub_zfs_to_cpu64 ((bp)->blk_prop, endian) >> 16) & 0xffff) + 1)
	  << SPA_MINBLOCKSHIFT);
}

static grub_uint64_t
dva_get_offset (dva_t * dva, grub_zfs_endian_t endian)
{
  grub_dprintf ("zfs", "dva=%llx, %llx\n", 
		(unsigned long long) dva->dva_word[0], 
		(unsigned long long) dva->dva_word[1]);
  return grub_zfs_to_cpu64 ((dva)->dva_word[1], 
			    endian) << SPA_MINBLOCKSHIFT;
}


/*
 * Read a block of data based on the gang block address dva,
 * and put its data in buf.
 *
 */
static grub_err_t
zio_read_gang (blkptr_t * bp, grub_zfs_endian_t endian, dva_t * dva, void *buf,
	       struct grub_zfs_data *data)
{
  zio_gbh_phys_t *zio_gb;
  grub_uint64_t offset, sector;
  unsigned i;
  grub_err_t err;
  zio_cksum_t zc;

  grub_memset (&zc, 0, sizeof (zc));

  zio_gb = grub_malloc (SPA_GANGBLOCKSIZE);
  if (!zio_gb)
    return grub_errno;
  grub_dprintf ("zfs", endian == LITTLE_ENDIAN ? "little-endian gang\n"
		:"big-endian gang\n");
  offset = dva_get_offset (dva, endian);
  sector = DVA_OFFSET_TO_PHYS_SECTOR (offset);
  grub_dprintf ("zfs", "offset=%llx\n", (unsigned long long) offset);

  /* read in the gang block header */
  err = grub_disk_read (data->disk, sector, 0, SPA_GANGBLOCKSIZE,
			(char *) zio_gb);
  if (err)
    {
      grub_free (zio_gb);
      return err;
    }

  /* XXX */
  /* self checksuming the gang block header */
  ZIO_SET_CHECKSUM (&zc, DVA_GET_VDEV (dva),
		    dva_get_offset (dva, endian), bp->blk_birth, 0);
  err = zio_checksum_verify (zc, ZIO_CHECKSUM_GANG_HEADER, endian,
			     (char *) zio_gb, SPA_GANGBLOCKSIZE);
  if (err)
    {
      grub_free (zio_gb);
      return err;
    }

  endian = (grub_zfs_to_cpu64 (bp->blk_prop, endian) >> 63) & 1;

  for (i = 0; i < SPA_GBH_NBLKPTRS; i++)
    {
      if (zio_gb->zg_blkptr[i].blk_birth == 0)
	continue;

      err = zio_read_data (&zio_gb->zg_blkptr[i], endian, buf, data);
      if (err)
	{
	  grub_free (zio_gb);
	  return err;
	}
      buf = (char *) buf + get_psize (&zio_gb->zg_blkptr[i], endian);
    }
  grub_free (zio_gb);
  return GRUB_ERR_NONE;
}

/*
 * Read in a block of raw data to buf.
 */
static grub_err_t
zio_read_data (blkptr_t * bp, grub_zfs_endian_t endian, void *buf, 
	       struct grub_zfs_data *data)
{
  int i, psize;
  grub_err_t err = GRUB_ERR_NONE;

  psize = get_psize (bp, endian);

  /* pick a good dva from the block pointer */
  for (i = 0; i < SPA_DVAS_PER_BP; i++)
    {
      grub_uint64_t offset, sector;

      if (bp->blk_dva[i].dva_word[0] == 0 && bp->blk_dva[i].dva_word[1] == 0)
	continue;

      if ((grub_zfs_to_cpu64 (bp->blk_dva[i].dva_word[1], endian)>>63) & 1)
	err = zio_read_gang (bp, endian, &bp->blk_dva[i], buf, data);
      else
	{
	  /* read in a data block */
	  offset = dva_get_offset (&bp->blk_dva[i], endian);
	  sector = DVA_OFFSET_TO_PHYS_SECTOR (offset);
	  err = grub_disk_read (data->disk, sector, 0, psize, buf); 
	}
      if (!err)
	return GRUB_ERR_NONE;
      grub_errno = GRUB_ERR_NONE;
    }

  if (!err)
    err = grub_error (GRUB_ERR_BAD_FS, "couldn't find a valid DVA");
  grub_errno = err;

  return err;
}

/*
 * Read in a block of data, verify its checksum, decompress if needed,
 * and put the uncompressed data in buf.
 */
static grub_err_t
zio_read (blkptr_t * bp, grub_zfs_endian_t endian, void **buf, 
	  grub_size_t *size, struct grub_zfs_data *data)
{
  grub_size_t lsize, psize;
  unsigned int comp;
  char *compbuf = NULL;
  grub_err_t err;
  zio_cksum_t zc = bp->blk_cksum;
  grub_uint32_t checksum;

  *buf = NULL;

  checksum = (grub_zfs_to_cpu64((bp)->blk_prop, endian) >> 40) & 0xff;
  comp = (grub_zfs_to_cpu64((bp)->blk_prop, endian)>>32) & 0x7;
  lsize = (BP_IS_HOLE(bp) ? 0 :
	   (((grub_zfs_to_cpu64 ((bp)->blk_prop, endian) & 0xffff) + 1)
	    << SPA_MINBLOCKSHIFT));
  psize = get_psize (bp, endian);

  if (size)
    *size = lsize;

  if (comp >= ZIO_COMPRESS_FUNCTIONS)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		       "compression algorithm %u not supported\n", (unsigned int) comp);

  if (comp != ZIO_COMPRESS_OFF && decomp_table[comp].decomp_func == NULL)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		       "compression algorithm %s not supported\n", decomp_table[comp].name);

  if (comp != ZIO_COMPRESS_OFF)
    {
      compbuf = grub_malloc (psize);
      if (! compbuf)
	return grub_errno;
    }
  else
    compbuf = *buf = grub_malloc (lsize);

  grub_dprintf ("zfs", "endian = %d\n", endian);
  err = zio_read_data (bp, endian, compbuf, data);
  if (err)
    {
      grub_free (compbuf);
      *buf = NULL;
      return err;
    }

  err = zio_checksum_verify (zc, checksum, endian, compbuf, psize);
  if (err)
    {
      grub_dprintf ("zfs", "incorrect checksum\n");
      grub_free (compbuf);
      *buf = NULL;
      return err;
    }

  if (comp != ZIO_COMPRESS_OFF)
    {
      *buf = grub_malloc (lsize);
      if (!*buf)
	{
	  grub_free (compbuf);
	  return grub_errno;
	}

      err = decomp_table[comp].decomp_func (compbuf, *buf, psize, lsize);
      grub_free (compbuf);
      if (err)
	{
	  grub_free (*buf);
	  *buf = NULL;
	  return err;
	}
    }

  return GRUB_ERR_NONE;
}

/*
 * Get the block from a block id.
 * push the block onto the stack.
 *
 */
static grub_err_t
dmu_read (dnode_end_t * dn, grub_uint64_t blkid, void **buf, 
	  grub_zfs_endian_t *endian_out, struct grub_zfs_data *data)
{
  int idx, level;
  blkptr_t *bp_array = dn->dn.dn_blkptr;
  int epbs = dn->dn.dn_indblkshift - SPA_BLKPTRSHIFT;
  blkptr_t *bp, *tmpbuf = 0;
  grub_zfs_endian_t endian;
  grub_err_t err = GRUB_ERR_NONE;

  bp = grub_malloc (sizeof (blkptr_t));
  if (!bp)
    return grub_errno;

  endian = dn->endian;
  for (level = dn->dn.dn_nlevels - 1; level >= 0; level--)
    {
      grub_dprintf ("zfs", "endian = %d\n", endian);
      idx = (blkid >> (epbs * level)) & ((1 << epbs) - 1);
      *bp = bp_array[idx];
      if (bp_array != dn->dn.dn_blkptr)
	{
	  grub_free (bp_array);
	  bp_array = 0;
	}

      if (BP_IS_HOLE (bp))
	{
	  grub_size_t size = grub_zfs_to_cpu16 (dn->dn.dn_datablkszsec, 
						dn->endian) 
	    << SPA_MINBLOCKSHIFT;
	  *buf = grub_malloc (size);
	  if (*buf)
	    {
	      err = grub_errno;
	      break;
	    }
	  grub_memset (*buf, 0, size);
	  endian = (grub_zfs_to_cpu64 (bp->blk_prop, endian) >> 63) & 1;
	  break;
	}
      if (level == 0)
	{
	  grub_dprintf ("zfs", "endian = %d\n", endian);
	  err = zio_read (bp, endian, buf, 0, data);
	  endian = (grub_zfs_to_cpu64 (bp->blk_prop, endian) >> 63) & 1;
	  break;
	}
      grub_dprintf ("zfs", "endian = %d\n", endian);
      err = zio_read (bp, endian, (void **) &tmpbuf, 0, data);
      endian = (grub_zfs_to_cpu64 (bp->blk_prop, endian) >> 63) & 1;
      if (err)
	break;
      bp_array = tmpbuf;
    }
  if (bp_array != dn->dn.dn_blkptr)
    grub_free (bp_array);
  if (endian_out)
    *endian_out = endian;

  grub_free (bp);
  return err;
}

/*
 * mzap_lookup: Looks up property described by "name" and returns the value
 * in "value".
 */
static grub_err_t
mzap_lookup (mzap_phys_t * zapobj, grub_zfs_endian_t endian,
	     int objsize, char *name, grub_uint64_t * value)
{
  int i, chunks;
  mzap_ent_phys_t *mzap_ent = zapobj->mz_chunk;

  chunks = objsize / MZAP_ENT_LEN - 1;
  for (i = 0; i < chunks; i++)
    {
      if (grub_strcmp (mzap_ent[i].mze_name, name) == 0)
	{
	  *value = grub_zfs_to_cpu64 (mzap_ent[i].mze_value, endian);
	  return GRUB_ERR_NONE;
	}
    }

  return grub_error (GRUB_ERR_FILE_NOT_FOUND, "couldn't find %s", name);
}

static int
mzap_iterate (mzap_phys_t * zapobj, grub_zfs_endian_t endian, int objsize, 
	      int NESTED_FUNC_ATTR (*hook) (const char *name, 
					    grub_uint64_t val))
{
  int i, chunks;
  mzap_ent_phys_t *mzap_ent = zapobj->mz_chunk;

  chunks = objsize / MZAP_ENT_LEN - 1;
  for (i = 0; i < chunks; i++)
    {
      grub_dprintf ("zfs", "zap: name = %s, value = %llx, cd = %x\n",
		    mzap_ent[i].mze_name, (long long)mzap_ent[i].mze_value,
		    (int)mzap_ent[i].mze_cd);
      if (hook (mzap_ent[i].mze_name, 
		grub_zfs_to_cpu64 (mzap_ent[i].mze_value, endian)))
	return 1;
    }

  return 0;
}

static grub_uint64_t
zap_hash (grub_uint64_t salt, const char *name)
{
  static grub_uint64_t table[256];
  const grub_uint8_t *cp;
  grub_uint8_t c;
  grub_uint64_t crc = salt;

  if (table[128] == 0)
    {
      grub_uint64_t *ct;
      int i, j;
      for (i = 0; i < 256; i++)
	{
	  for (ct = table + i, *ct = i, j = 8; j > 0; j--)
	    *ct = (*ct >> 1) ^ (-(*ct & 1) & ZFS_CRC64_POLY);
	}
    }

  for (cp = (const grub_uint8_t *) name; (c = *cp) != '\0'; cp++)
    crc = (crc >> 8) ^ table[(crc ^ c) & 0xFF];

  /*
   * Only use 28 bits, since we need 4 bits in the cookie for the
   * collision differentiator.  We MUST use the high bits, since
   * those are the onces that we first pay attention to when
   * chosing the bucket.
   */
  crc &= ~((1ULL << (64 - ZAP_HASHBITS)) - 1);

  return (crc);
}

/*
 * Only to be used on 8-bit arrays.
 * array_len is actual len in bytes (not encoded le_value_length).
 * buf is null-terminated.
 */
/* XXX */
static int
zap_leaf_array_equal (zap_leaf_phys_t * l, grub_zfs_endian_t endian,
		      int blksft, int chunk, int array_len, const char *buf)
{
  int bseen = 0;

  while (bseen < array_len)
    {
      struct zap_leaf_array *la = &ZAP_LEAF_CHUNK (l, blksft, chunk).l_array;
      int toread = MIN (array_len - bseen, ZAP_LEAF_ARRAY_BYTES);

      if (chunk >= ZAP_LEAF_NUMCHUNKS (blksft))
	return (0);

      if (grub_memcmp (la->la_array, buf + bseen, toread) != 0)
	break;
      chunk = grub_zfs_to_cpu16 (la->la_next, endian);
      bseen += toread;
    }
  return (bseen == array_len);
}

/* XXX */
static grub_err_t
zap_leaf_array_get (zap_leaf_phys_t * l, grub_zfs_endian_t endian, int blksft, 
		    int chunk, int array_len, char *buf)
{
  int bseen = 0;

  while (bseen < array_len)
    {
      struct zap_leaf_array *la = &ZAP_LEAF_CHUNK (l, blksft, chunk).l_array;
      int toread = MIN (array_len - bseen, ZAP_LEAF_ARRAY_BYTES);

      if (chunk >= ZAP_LEAF_NUMCHUNKS (blksft))
	/* Don't use grub_error because this error is to be ignored.  */
	return GRUB_ERR_BAD_FS;

      grub_memcpy (buf + bseen,la->la_array,  toread);
      chunk = grub_zfs_to_cpu16 (la->la_next, endian);
      bseen += toread;
    }
  return GRUB_ERR_NONE;
}


/*
 * Given a zap_leaf_phys_t, walk thru the zap leaf chunks to get the
 * value for the property "name".
 *
 */
/* XXX */
static grub_err_t
zap_leaf_lookup (zap_leaf_phys_t * l, grub_zfs_endian_t endian,
		 int blksft, grub_uint64_t h,
		 const char *name, grub_uint64_t * value)
{
  grub_uint16_t chunk;
  struct zap_leaf_entry *le;

  /* Verify if this is a valid leaf block */
  if (grub_zfs_to_cpu64 (l->l_hdr.lh_block_type, endian) != ZBT_LEAF)
    return grub_error (GRUB_ERR_BAD_FS, "invalid leaf type");
  if (grub_zfs_to_cpu32 (l->l_hdr.lh_magic, endian) != ZAP_LEAF_MAGIC)
    return grub_error (GRUB_ERR_BAD_FS, "invalid leaf magic");

  for (chunk = grub_zfs_to_cpu16 (l->l_hash[LEAF_HASH (blksft, h)], endian);
       chunk != CHAIN_END; chunk = le->le_next)
    {

      if (chunk >= ZAP_LEAF_NUMCHUNKS (blksft))
	return grub_error (GRUB_ERR_BAD_FS, "invalid chunk number");

      le = ZAP_LEAF_ENTRY (l, blksft, chunk);

      /* Verify the chunk entry */
      if (le->le_type != ZAP_CHUNK_ENTRY)
	return grub_error (GRUB_ERR_BAD_FS, "invalid chunk entry");

      if (grub_zfs_to_cpu64 (le->le_hash,endian) != h)
	continue;

      grub_dprintf ("zfs", "fzap: length %d\n", (int) le->le_name_length);

      if (zap_leaf_array_equal (l, endian, blksft, 
				grub_zfs_to_cpu16 (le->le_name_chunk,endian),
				grub_zfs_to_cpu16 (le->le_name_length, endian),
				name))
	{
	  struct zap_leaf_array *la;
	  grub_uint8_t *ip;

	  if (le->le_int_size != 8 || le->le_value_length != 1)
	    return grub_error (GRUB_ERR_BAD_FS, "invalid leaf chunk entry");

	  /* get the uint64_t property value */
	  la = &ZAP_LEAF_CHUNK (l, blksft, le->le_value_chunk).l_array;
	  ip = la->la_array;

	  *value = grub_be_to_cpu64 (la->la_array64);

	  return GRUB_ERR_NONE;
	}
    }

  return grub_error (GRUB_ERR_FILE_NOT_FOUND, "couldn't find %s", name);
}


/* Verify if this is a fat zap header block */
static grub_err_t
zap_verify (zap_phys_t *zap)
{
  if (zap->zap_magic != (grub_uint64_t) ZAP_MAGIC)
    return grub_error (GRUB_ERR_BAD_FS, "bad ZAP magic");

  if (zap->zap_flags != 0)
    return grub_error (GRUB_ERR_BAD_FS, "bad ZAP flags");

  if (zap->zap_salt == 0)
    return grub_error (GRUB_ERR_BAD_FS, "bad ZAP salt");

  return GRUB_ERR_NONE;
}

/*
 * Fat ZAP lookup
 *
 */
/* XXX */
static grub_err_t
fzap_lookup (dnode_end_t * zap_dnode, zap_phys_t * zap,
	     char *name, grub_uint64_t * value, struct grub_zfs_data *data)
{
  zap_leaf_phys_t *l;
  grub_uint64_t hash, idx, blkid;
  int blksft = zfs_log2 (grub_zfs_to_cpu16 (zap_dnode->dn.dn_datablkszsec, 
					    zap_dnode->endian) << DNODE_SHIFT);
  grub_err_t err;
  grub_zfs_endian_t leafendian;

  err = zap_verify (zap);
  if (err)
    return err;

  hash = zap_hash (zap->zap_salt, name);

  /* get block id from index */
  if (zap->zap_ptrtbl.zt_numblks != 0)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, 
		       "external pointer tables not supported");
  idx = ZAP_HASH_IDX (hash, zap->zap_ptrtbl.zt_shift);
  blkid = ((grub_uint64_t *) zap)[idx + (1 << (blksft - 3 - 1))];

  /* Get the leaf block */
  if ((1U << blksft) < sizeof (zap_leaf_phys_t))
    return grub_error (GRUB_ERR_BAD_FS, "ZAP leaf is too small");
  err = dmu_read (zap_dnode, blkid, (void **) &l, &leafendian, data);
  if (err)
    return err;

  err = zap_leaf_lookup (l, leafendian, blksft, hash, name, value);
  grub_free (l);
  return err;
}

/* XXX */
static int
fzap_iterate (dnode_end_t * zap_dnode, zap_phys_t * zap,
	     int NESTED_FUNC_ATTR (*hook) (const char *name, 
					   grub_uint64_t val), 
	     struct grub_zfs_data *data)
{
  zap_leaf_phys_t *l;
  grub_uint64_t idx, blkid;
  grub_uint16_t chunk;
  int blksft = zfs_log2 (grub_zfs_to_cpu16 (zap_dnode->dn.dn_datablkszsec, 
					    zap_dnode->endian) << DNODE_SHIFT);
  grub_err_t err;
  grub_zfs_endian_t endian;

  if (zap_verify (zap))
    return 0;

  /* get block id from index */
  if (zap->zap_ptrtbl.zt_numblks != 0)
    {
      grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, 
		  "external pointer tables not supported");
      return 0;
    }
  /* Get the leaf block */
  if ((1U << blksft) < sizeof (zap_leaf_phys_t))
    {
      grub_error (GRUB_ERR_BAD_FS, "ZAP leaf is too small");
      return 0;
    }
  for (idx = 0; idx < zap->zap_ptrtbl.zt_numblks; idx++)
    {
      blkid = ((grub_uint64_t *) zap)[idx + (1 << (blksft - 3 - 1))];

      err = dmu_read (zap_dnode, blkid, (void **) &l, &endian, data);
      if (err)
	{
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}

      /* Verify if this is a valid leaf block */
      if (grub_zfs_to_cpu64 (l->l_hdr.lh_block_type, endian) != ZBT_LEAF)
	{
	  grub_free (l);
	  continue;
	}
      if (grub_zfs_to_cpu32 (l->l_hdr.lh_magic, endian) != ZAP_LEAF_MAGIC)
	{
	  grub_free (l);
	  continue;
	}

      for (chunk = 0; chunk < ZAP_LEAF_NUMCHUNKS (blksft); chunk++)
	  {
	    char *buf;
	    struct zap_leaf_array *la;
	    struct zap_leaf_entry *le;
	    grub_uint64_t val;
	    le = ZAP_LEAF_ENTRY (l, blksft, chunk);

	    /* Verify the chunk entry */
	    if (le->le_type != ZAP_CHUNK_ENTRY)
	      continue;

	    buf = grub_malloc (grub_zfs_to_cpu16 (le->le_name_length, endian) 
			       + 1);
	    if (zap_leaf_array_get (l, endian, blksft, le->le_name_chunk,
				    le->le_name_length, buf))
	      {
		grub_free (buf);
		continue;
	      }
	    buf[le->le_name_length] = 0;

	    if (le->le_int_size != 8 
		|| grub_zfs_to_cpu16 (le->le_value_length, endian) != 1)
	      continue;

	    /* get the uint64_t property value */
	    la = &ZAP_LEAF_CHUNK (l, blksft, le->le_value_chunk).l_array;
	    val = grub_be_to_cpu64 (la->la_array64);
	    if (hook (buf, val))
	      return 1;
	    grub_free (buf);
	  }
    }
  return 0;
}


/*
 * Read in the data of a zap object and find the value for a matching
 * property name.
 *
 */
static grub_err_t
zap_lookup (dnode_end_t * zap_dnode, char *name, grub_uint64_t * val,
	    struct grub_zfs_data *data)
{
  grub_uint64_t block_type;
  int size;
  void *zapbuf;
  grub_err_t err;
  grub_zfs_endian_t endian;

  grub_dprintf ("zfs", "looking for '%s'\n", name);

  /* Read in the first block of the zap object data. */
  size = grub_zfs_to_cpu16 (zap_dnode->dn.dn_datablkszsec, 
			    zap_dnode->endian) << SPA_MINBLOCKSHIFT;
  err = dmu_read (zap_dnode, 0, &zapbuf, &endian, data);
  if (err)
    return err;
  block_type = grub_zfs_to_cpu64 (*((grub_uint64_t *) zapbuf), endian);

  grub_dprintf ("zfs", "zap read\n");

  if (block_type == ZBT_MICRO)
    {
      grub_dprintf ("zfs", "micro zap\n");
      err = (mzap_lookup (zapbuf, endian, size, name, val));
      grub_dprintf ("zfs", "returned %d\n", err);      
      grub_free (zapbuf);
      return err;
    }
  else if (block_type == ZBT_HEADER)
    {
      grub_dprintf ("zfs", "fat zap\n");
      /* this is a fat zap */
      err = (fzap_lookup (zap_dnode, zapbuf, name, val, data));
      grub_dprintf ("zfs", "returned %d\n", err);      
      grub_free (zapbuf);
      return err;
    }

  return grub_error (GRUB_ERR_BAD_FS, "unknown ZAP type");
}

static int
zap_iterate (dnode_end_t * zap_dnode, 
	     int NESTED_FUNC_ATTR (*hook) (const char *name, grub_uint64_t val),
	     struct grub_zfs_data *data)
{
  grub_uint64_t block_type;
  int size;
  void *zapbuf;
  grub_err_t err;
  int ret;
  grub_zfs_endian_t endian;

  /* Read in the first block of the zap object data. */
  size = grub_zfs_to_cpu16 (zap_dnode->dn.dn_datablkszsec, zap_dnode->endian) << SPA_MINBLOCKSHIFT;
  err = dmu_read (zap_dnode, 0, &zapbuf, &endian, data);
  if (err)
    return 0;
  block_type = grub_zfs_to_cpu64 (*((grub_uint64_t *) zapbuf), endian);

  grub_dprintf ("zfs", "zap read\n");

  if (block_type == ZBT_MICRO)
    {
      grub_dprintf ("zfs", "micro zap\n");
      ret = mzap_iterate (zapbuf, endian, size, hook);
      grub_free (zapbuf);
      return ret;
    }
  else if (block_type == ZBT_HEADER)
    {
      grub_dprintf ("zfs", "fat zap\n");
      /* this is a fat zap */
      ret = fzap_iterate (zap_dnode, zapbuf, hook, data);
      grub_free (zapbuf);
      return ret;
    }
  grub_error (GRUB_ERR_BAD_FS, "unknown ZAP type");
  return 0;
}


/*
 * Get the dnode of an object number from the metadnode of an object set.
 *
 * Input
 *	mdn - metadnode to get the object dnode
 *	objnum - object number for the object dnode
 *	buf - data buffer that holds the returning dnode
 */
static grub_err_t
dnode_get (dnode_end_t * mdn, grub_uint64_t objnum, grub_uint8_t type,
	   dnode_end_t * buf, struct grub_zfs_data *data)
{
  grub_uint64_t blkid, blksz;	/* the block id this object dnode is in */
  int epbs;			/* shift of number of dnodes in a block */
  int idx;			/* index within a block */
  dnode_phys_t *dnbuf;
  grub_err_t err;
  grub_zfs_endian_t endian;

  blksz = grub_zfs_to_cpu16 (mdn->dn.dn_datablkszsec, 
			     mdn->endian) << SPA_MINBLOCKSHIFT;
  epbs = zfs_log2 (blksz) - DNODE_SHIFT;
  blkid = objnum >> epbs;
  idx = objnum & ((1 << epbs) - 1);

  if (data->dnode_buf != NULL && grub_memcmp (data->dnode_mdn, mdn, 
					      sizeof (*mdn)) == 0 
      && objnum >= data->dnode_start && objnum < data->dnode_end)
    {
      grub_memmove (&(buf->dn), &(data->dnode_buf)[idx], DNODE_SIZE);
      buf->endian = data->dnode_endian;
      if (type && buf->dn.dn_type != type) 
	return grub_error(GRUB_ERR_BAD_FS, "incorrect dnode type"); 
      return GRUB_ERR_NONE;
    }

  grub_dprintf ("zfs", "endian = %d, blkid=%llx\n", mdn->endian, 
		(unsigned long long) blkid);
  err = dmu_read (mdn, blkid, (void **) &dnbuf, &endian, data);
  if (err)
    return err;
  grub_dprintf ("zfs", "alive\n");

  grub_free (data->dnode_buf);
  grub_free (data->dnode_mdn);
  data->dnode_mdn = grub_malloc (sizeof (*mdn));
  if (! data->dnode_mdn)
    {
      grub_errno = GRUB_ERR_NONE;
      data->dnode_buf = 0;
    }
  else
    {
      grub_memcpy (data->dnode_mdn, mdn, sizeof (*mdn));
      data->dnode_buf = dnbuf;
      data->dnode_start = blkid << epbs;
      data->dnode_end = (blkid + 1) << epbs;
      data->dnode_endian = endian;
    }

  grub_memmove (&(buf->dn), &dnbuf[idx], DNODE_SIZE);
  buf->endian = endian;
  if (type && buf->dn.dn_type != type) 
    return grub_error(GRUB_ERR_BAD_FS, "incorrect dnode type"); 

  return GRUB_ERR_NONE;
}

/*
 * Get the file dnode for a given file name where mdn is the meta dnode
 * for this ZFS object set. When found, place the file dnode in dn.
 * The 'path' argument will be mangled.
 *
 */
static grub_err_t
dnode_get_path (dnode_end_t * mdn, const char *path_in, dnode_end_t * dn,
		struct grub_zfs_data *data)
{
  grub_uint64_t objnum, version;
  char *cname, ch;
  grub_err_t err = GRUB_ERR_NONE;
  char *path, *path_buf;
  struct dnode_chain
  {
    struct dnode_chain *next;
    dnode_end_t dn; 
  };
  struct dnode_chain *dnode_path = 0, *dn_new, *root;

  dn_new = grub_malloc (sizeof (*dn_new));
  if (! dn_new)
    return grub_errno;
  dn_new->next = 0;
  dnode_path = root = dn_new;

  err = dnode_get (mdn, MASTER_NODE_OBJ, DMU_OT_MASTER_NODE, 
		   &(dnode_path->dn), data);
  if (err)
    {
      grub_free (dn_new);
      return err;
    }

  err = zap_lookup (&(dnode_path->dn), ZPL_VERSION_STR, &version, data);
  if (err)
    {
      grub_free (dn_new);
      return err;
    }
  if (version > ZPL_VERSION)
    {
      grub_free (dn_new);
      return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "too new ZPL version");
    }
  
  err = zap_lookup (&(dnode_path->dn), ZFS_ROOT_OBJ, &objnum, data);
  if (err)
    {
      grub_free (dn_new);
      return err;
    }

  err = dnode_get (mdn, objnum, 0, &(dnode_path->dn), data);
  if (err)
    {
      grub_free (dn_new);
      return err;
    }

  path = path_buf = grub_strdup (path_in);
  if (!path_buf)
    {
      grub_free (dn_new);
      return grub_errno;
    }
  
  while (1)
    {
      /* skip leading slashes */
      while (*path == '/')
	path++;
      if (!*path)
	break;
      /* get the next component name */
      cname = path;
      while (*path && *path != '/')
	path++;
      /* Skip dot.  */
      if (cname + 1 == path && cname[0] == '.')
	continue;
      /* Handle double dot.  */
      if (cname + 2 == path && cname[0] == '.' && cname[1] == '.')
	{
	  if (dn_new->next)
	    {
	      dn_new = dnode_path;
	      dnode_path = dn_new->next;
	      grub_free (dn_new);
	    }
	  else
	    {
	      err = grub_error (GRUB_ERR_FILE_NOT_FOUND, 
				"can't resolve ..");
	      break;
	    }
	  continue;
	}

      ch = *path;
      *path = 0;		/* ensure null termination */

      if (dnode_path->dn.dn.dn_type != DMU_OT_DIRECTORY_CONTENTS)
	{
	  grub_free (path_buf);
	  return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");
	}
      err = zap_lookup (&(dnode_path->dn), cname, &objnum, data);
      if (err)
	break;

      dn_new = grub_malloc (sizeof (*dn_new));
      if (! dn_new)
	{
	  err = grub_errno;
	  break;
	}
      dn_new->next = dnode_path;
      dnode_path = dn_new;

      objnum = ZFS_DIRENT_OBJ (objnum);
      err = dnode_get (mdn, objnum, 0, &(dnode_path->dn), data);
      if (err)
	break;

      *path = ch;
#if 0
      if (((grub_zfs_to_cpu64(((znode_phys_t *) DN_BONUS (&dnode_path->dn.dn))->zp_mode, dnode_path->dn.endian) >> 12) & 0xf) == 0xa && ch)
	{
	  char *oldpath = path, *oldpathbuf = path_buf;
	  path = path_buf 
	    = grub_malloc (sizeof (dnode_path->dn.dn.dn_bonus) 
			   - sizeof (znode_phys_t) + grub_strlen (oldpath) + 1);
	  if (!path_buf)
	    {
	      grub_free (oldpathbuf);
	      return grub_errno;
	    }
	  grub_memcpy (path, 
		       (char *) DN_BONUS(&dnode_path->dn.dn) + sizeof (znode_phys_t),
		       sizeof (dnode_path->dn.dn.dn_bonus) - sizeof (znode_phys_t));
	  path [sizeof (dnode_path->dn.dn.dn_bonus) - sizeof (znode_phys_t)] = 0;
	  grub_memcpy (path + grub_strlen (path), oldpath, 
		       grub_strlen (oldpath) + 1);
	  
	  grub_free (oldpathbuf);
	  if (path[0] != '/')
	    {
	      dn_new = dnode_path;
	      dnode_path = dn_new->next;
	      grub_free (dn_new);
	    }
	  else while (dnode_path != root)
	    {
	      dn_new = dnode_path;
	      dnode_path = dn_new->next;
	      grub_free (dn_new);
	    }
	}
#endif
    }

  if (!err)
    grub_memcpy (dn, &(dnode_path->dn), sizeof (*dn));

  while (dnode_path)
    {
      dn_new = dnode_path->next;
      grub_free (dnode_path);
      dnode_path = dn_new;
    }
  grub_free (path_buf);
  return err;
}

#if 0
/*
 * Get the default 'bootfs' property value from the rootpool.
 *
 */
static grub_err_t
get_default_bootfsobj (dnode_phys_t * mosmdn, grub_uint64_t * obj,
		       struct grub_zfs_data *data)
{
  grub_uint64_t objnum = 0;
  dnode_phys_t *dn;
  if (!dn)
    return grub_errno;

  if ((grub_errno = dnode_get (mosmdn, DMU_POOL_DIRECTORY_OBJECT,
			       DMU_OT_OBJECT_DIRECTORY, dn, data)))
    {
      grub_free (dn);
      return (grub_errno);
    }

  /*
   * find the object number for 'pool_props', and get the dnode
   * of the 'pool_props'.
   */
  if (zap_lookup (dn, DMU_POOL_PROPS, &objnum, data))
    {
      grub_free (dn);
      return (GRUB_ERR_BAD_FS);
    }
  if ((grub_errno = dnode_get (mosmdn, objnum, DMU_OT_POOL_PROPS, dn, data)))
    {
      grub_free (dn);
      return (grub_errno);
    }
  if (zap_lookup (dn, ZPOOL_PROP_BOOTFS, &objnum, data))
    {
      grub_free (dn);
      return (GRUB_ERR_BAD_FS);
    }

  if (!objnum)
    {
      grub_free (dn);
      return (GRUB_ERR_BAD_FS);
    }

  *obj = objnum;
  return (0);
}
#endif
/*
 * Given a MOS metadnode, get the metadnode of a given filesystem name (fsname),
 * e.g. pool/rootfs, or a given object number (obj), e.g. the object number
 * of pool/rootfs.
 *
 * If no fsname and no obj are given, return the DSL_DIR metadnode.
 * If fsname is given, return its metadnode and its matching object number.
 * If only obj is given, return the metadnode for this object number.
 *
 */
static grub_err_t
get_filesystem_dnode (dnode_end_t * mosmdn, char *fsname,
		      dnode_end_t * mdn, struct grub_zfs_data *data)
{
  grub_uint64_t objnum;
  grub_err_t err;

  grub_dprintf ("zfs", "endian = %d\n", mosmdn->endian);

  err = dnode_get (mosmdn, DMU_POOL_DIRECTORY_OBJECT, 
		   DMU_OT_OBJECT_DIRECTORY, mdn, data);
  if (err)
    return err;

  grub_dprintf ("zfs", "alive\n");

  err = zap_lookup (mdn, DMU_POOL_ROOT_DATASET, &objnum, data);
  if (err)
    return err;

  grub_dprintf ("zfs", "alive\n");

  err = dnode_get (mosmdn, objnum, DMU_OT_DSL_DIR, mdn, data);
  if (err)
    return err;

  grub_dprintf ("zfs", "alive\n");

  while (*fsname)
    {
      grub_uint64_t childobj;
      char *cname, ch;
 
      while (*fsname == '/')
	fsname++;

      if (! *fsname || *fsname == '@')
	break;

      cname = fsname;
      while (*fsname && !grub_isspace (*fsname) && *fsname != '/')
	fsname++;
      ch = *fsname;
      *fsname = 0;

      childobj = grub_zfs_to_cpu64 ((((dsl_dir_phys_t *) DN_BONUS (&mdn->dn)))->dd_child_dir_zapobj, mdn->endian);
      err = dnode_get (mosmdn, childobj,
		       DMU_OT_DSL_DIR_CHILD_MAP, mdn, data);
      if (err)
	return err;

      err = zap_lookup (mdn, cname, &objnum, data);
      if (err)
	return err;

      err = dnode_get (mosmdn, objnum, DMU_OT_DSL_DIR, mdn, data);
      if (err)
	return err;

      *fsname = ch;
    }
  return GRUB_ERR_NONE;
}

static grub_err_t
make_mdn (dnode_end_t * mdn, struct grub_zfs_data *data)
{
  objset_phys_t *osp;
  blkptr_t *bp;
  grub_size_t ospsize;
  grub_err_t err;

  grub_dprintf ("zfs", "endian = %d\n", mdn->endian);

  bp = &(((dsl_dataset_phys_t *) DN_BONUS (&mdn->dn))->ds_bp);
  err = zio_read (bp, mdn->endian, (void **) &osp, &ospsize, data);
  if (err)
    return err;
  if (ospsize < OBJSET_PHYS_SIZE_V14)
    {
      grub_free (osp);
      return grub_error (GRUB_ERR_BAD_FS, "too small osp");
    }

  mdn->endian = (grub_zfs_to_cpu64 (bp->blk_prop, mdn->endian)>>63) & 1;
  grub_memmove ((char *) &(mdn->dn), (char *) &osp->os_meta_dnode, DNODE_SIZE);
  grub_free (osp);
  return GRUB_ERR_NONE;
}

static grub_err_t
dnode_get_fullpath (const char *fullpath, dnode_end_t * mdn,
		    grub_uint64_t *mdnobj, dnode_end_t * dn, int *isfs,
		    struct grub_zfs_data *data)
{
  char *fsname, *snapname;
  const char *ptr_at, *filename;
  grub_uint64_t headobj;
  grub_err_t err;

  ptr_at = grub_strchr (fullpath, '@');
  if (! ptr_at)
    {
      *isfs = 1;
      filename = 0;
      snapname = 0;
      fsname = grub_strdup (fullpath);
    }
  else
    {
      const char *ptr_slash = grub_strchr (ptr_at, '/');

      *isfs = 0;
      fsname = grub_malloc (ptr_at - fullpath + 1);
      if (!fsname)
	return grub_errno;
      grub_memcpy (fsname, fullpath, ptr_at - fullpath);
      fsname[ptr_at - fullpath] = 0;
      if (ptr_at[1] && ptr_at[1] != '/')
	{
	  snapname = grub_malloc (ptr_slash - ptr_at);
	  if (!snapname)
	    {
	      grub_free (fsname);
	      return grub_errno;
	    }
	  grub_memcpy (snapname, ptr_at + 1, ptr_slash - ptr_at - 1);
	  snapname[ptr_slash - ptr_at - 1] = 0;
	}
      else
	snapname = 0;
      if (ptr_slash)
	filename = ptr_slash;
      else
	filename = "/";
      grub_dprintf ("zfs", "fsname = '%s' snapname='%s' filename = '%s'\n", 
		    fsname, snapname, filename);
    }
  grub_dprintf ("zfs", "alive\n");
  err = get_filesystem_dnode (&(data->mos), fsname, dn, data);
  if (err)
    {
      grub_free (fsname);
      grub_free (snapname);
      return err;
    }

  grub_dprintf ("zfs", "alive\n");

  headobj = grub_zfs_to_cpu64 (((dsl_dir_phys_t *) DN_BONUS (&dn->dn))->dd_head_dataset_obj, dn->endian);

  grub_dprintf ("zfs", "endian = %d\n", mdn->endian);

  err = dnode_get (&(data->mos), headobj, DMU_OT_DSL_DATASET, mdn, data);
  if (err)
    {
      grub_free (fsname);
      grub_free (snapname);
      return err;
    }
  grub_dprintf ("zfs", "endian = %d\n", mdn->endian);

  if (snapname)
    {
      grub_uint64_t snapobj;

      snapobj = grub_zfs_to_cpu64 (((dsl_dataset_phys_t *) DN_BONUS (&mdn->dn))->ds_snapnames_zapobj, mdn->endian);

      err = dnode_get (&(data->mos), snapobj, 
		       DMU_OT_DSL_DS_SNAP_MAP, mdn, data);
      if (!err)
	err = zap_lookup (mdn, snapname, &headobj, data);
      if (!err)
	err = dnode_get (&(data->mos), headobj, DMU_OT_DSL_DATASET, mdn, data);
      if (err)
	{
	  grub_free (fsname);
	  grub_free (snapname);
	  return err;
	}
    }

  if (mdnobj)
    *mdnobj = headobj;

  make_mdn (mdn, data);
  
  grub_dprintf ("zfs", "endian = %d\n", mdn->endian);

  if (*isfs)
    {
      grub_free (fsname);
      grub_free (snapname);      
      return GRUB_ERR_NONE;
    }
  err = dnode_get_path (mdn, filename, dn, data);
  grub_free (fsname);
  grub_free (snapname);
  return err;
}

/*
 * For a given XDR packed nvlist, verify the first 4 bytes and move on.
 *
 * An XDR packed nvlist is encoded as (comments from nvs_xdr_create) :
 *
 *      encoding method/host endian     (4 bytes)
 *      nvl_version                     (4 bytes)
 *      nvl_nvflag                      (4 bytes)
 *	encoded nvpairs:
 *		encoded size of the nvpair      (4 bytes)
 *		decoded size of the nvpair      (4 bytes)
 *		name string size                (4 bytes)
 *		name string data                (sizeof(NV_ALIGN4(string))
 *		data type                       (4 bytes)
 *		# of elements in the nvpair     (4 bytes)
 *		data
 *      2 zero's for the last nvpair
 *		(end of the entire list)	(8 bytes)
 *
 */

static int
nvlist_find_value (char *nvlist, char *name, int valtype, char **val,
		   grub_size_t *size_out, grub_size_t *nelm_out)
{
  int name_len, type, encode_size;
  char *nvpair, *nvp_name;

  /* Verify if the 1st and 2nd byte in the nvlist are valid. */
  /* NOTE: independently of what endianness header announces all 
     subsequent values are big-endian.  */
  if (nvlist[0] != NV_ENCODE_XDR || (nvlist[1] != NV_LITTLE_ENDIAN 
				     && nvlist[1] != NV_BIG_ENDIAN))
    {
      grub_dprintf ("zfs", "incorrect nvlist header\n");
      grub_error (GRUB_ERR_BAD_FS, "incorrect nvlist");
      return 0;
    }

  /* skip the header, nvl_version, and nvl_nvflag */
  nvlist = nvlist + 4 * 3;
  /*
   * Loop thru the nvpair list
   * The XDR representation of an integer is in big-endian byte order.
   */
  while ((encode_size = grub_be_to_cpu32 (*(grub_uint32_t *) nvlist)))
    {
      int nelm;

      nvpair = nvlist + 4 * 2;	/* skip the encode/decode size */

      name_len = grub_be_to_cpu32 (*(grub_uint32_t *) nvpair);
      nvpair += 4;

      nvp_name = nvpair;
      nvpair = nvpair + ((name_len + 3) & ~3);	/* align */

      type = grub_be_to_cpu32 (*(grub_uint32_t *) nvpair);
      nvpair += 4;

      nelm = grub_be_to_cpu32 (*(grub_uint32_t *) nvpair);
      if (nelm < 1)
	return grub_error (GRUB_ERR_BAD_FS, "empty nvpair");

      nvpair += 4;

      if ((grub_strncmp (nvp_name, name, name_len) == 0) && type == valtype)
	{
	  *val = nvpair;
	  *size_out = encode_size;
	  if (nelm_out)
	    *nelm_out = nelm;
	  return 1;
	}

      nvlist += encode_size;	/* goto the next nvpair */
    }
  return 0;
}

int
grub_zfs_nvlist_lookup_uint64 (char *nvlist, char *name, grub_uint64_t * out)
{
  char *nvpair;
  grub_size_t size;
  int found;

  found = nvlist_find_value (nvlist, name, DATA_TYPE_UINT64, &nvpair, &size, 0);
  if (!found)
    return 0;
  if (size < sizeof (grub_uint64_t))
    {
      grub_error (GRUB_ERR_BAD_FS, "invalid uint64");
      return 0;
    }

  *out = grub_be_to_cpu64 (*(grub_uint64_t *) nvpair);
  return 1;
}

char *
grub_zfs_nvlist_lookup_string (char *nvlist, char *name)
{
  char *nvpair;
  char *ret;
  grub_size_t slen;
  grub_size_t size;
  int found;

  found = nvlist_find_value (nvlist, name, DATA_TYPE_STRING, &nvpair, &size, 0);
  if (!found)
    return 0;
  if (size < 4)
    {
      grub_error (GRUB_ERR_BAD_FS, "invalid string");
      return 0;
    }
  slen = grub_be_to_cpu32 (*(grub_uint32_t *) nvpair);
  if (slen > size - 4)
    slen = size - 4;
  ret = grub_malloc (slen + 1);
  if (!ret)
    return 0;
  grub_memcpy (ret, nvpair + 4, slen);
  ret[slen] = 0;
  return ret;
}

char *
grub_zfs_nvlist_lookup_nvlist (char *nvlist, char *name)
{
  char *nvpair;
  char *ret;
  grub_size_t size;
  int found;

  found = nvlist_find_value (nvlist, name, DATA_TYPE_NVLIST, &nvpair,
			     &size, 0);
  if (!found)
    return 0;
  ret = grub_zalloc (size + 3 * sizeof (grub_uint32_t));
  if (!ret)
    return 0;
  grub_memcpy (ret, nvlist, sizeof (grub_uint32_t));

  grub_memcpy (ret + sizeof (grub_uint32_t), nvpair, size);
  return ret;
}

int
grub_zfs_nvlist_lookup_nvlist_array_get_nelm (char *nvlist, char *name)
{
  char *nvpair;
  grub_size_t nelm, size;
  int found;

  found = nvlist_find_value (nvlist, name, DATA_TYPE_NVLIST, &nvpair,
			     &size, &nelm);
  if (! found)
    return -1;
  return nelm;
}

char *
grub_zfs_nvlist_lookup_nvlist_array (char *nvlist, char *name,
				     grub_size_t index)
{
  char *nvpair, *nvpairptr;
  int found;
  char *ret;
  grub_size_t size;
  unsigned i;
  grub_size_t nelm;

  found = nvlist_find_value (nvlist, name, DATA_TYPE_NVLIST, &nvpair,
			     &size, &nelm);
  if (!found)
    return 0;
  if (index >= nelm)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, "trying to lookup past nvlist array");
      return 0;
    }

  nvpairptr = nvpair;

  for (i = 0; i < index; i++)
    {
      grub_uint32_t encode_size;

      /* skip the header, nvl_version, and nvl_nvflag */
      nvpairptr = nvpairptr + 4 * 2;

      while (nvpairptr < nvpair + size
	     && (encode_size = grub_be_to_cpu32 (*(grub_uint32_t *) nvpairptr)))
	nvlist += encode_size;	/* goto the next nvpair */

      nvlist = nvlist + 4 * 2;	/* skip the ending 2 zeros - 8 bytes */
    }

  if (nvpairptr >= nvpair + size
      || nvpairptr + grub_be_to_cpu32 (*(grub_uint32_t *) (nvpairptr + 4 * 2))
      >= nvpair + size)
    {
      grub_error (GRUB_ERR_BAD_FS, "incorrect nvlist array");
      return 0;
    }

  ret = grub_zalloc (grub_be_to_cpu32 (*(grub_uint32_t *) (nvpairptr + 4 * 2))
		     + 3 * sizeof (grub_uint32_t));
  if (!ret)
    return 0;
  grub_memcpy (ret, nvlist, sizeof (grub_uint32_t));

  grub_memcpy (ret + sizeof (grub_uint32_t), nvpairptr, size);
  return ret;
}

static grub_err_t
zfs_fetch_nvlist (struct grub_zfs_data * data, char **nvlist)
{
  grub_err_t err;

  *nvlist = grub_malloc (VDEV_PHYS_SIZE);
  /* Read in the vdev name-value pair list (112K). */
  err = grub_disk_read (data->disk, data->vdev_phys_sector, 0,
			VDEV_PHYS_SIZE, *nvlist);
  if (err)
    {
      grub_free (*nvlist);
      *nvlist = 0;
      return err;
    }
  return GRUB_ERR_NONE;
}

/*
 * Check the disk label information and retrieve needed vdev name-value pairs.
 *
 */
static grub_err_t
check_pool_label (struct grub_zfs_data *data)
{
  grub_uint64_t pool_state, txg = 0;
  char *nvlist;
#if 0
  char *nv;
#endif
  grub_uint64_t diskguid;
  grub_uint64_t version;
  int found;
  grub_err_t err;

  err = zfs_fetch_nvlist (data, &nvlist);
  if (err)
    return err;

  grub_dprintf ("zfs", "check 2 passed\n");

  found = grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_POOL_STATE,
					 &pool_state);
  if (! found)
    {
      grub_free (nvlist);
      if (! grub_errno)
	grub_error (GRUB_ERR_BAD_FS, ZPOOL_CONFIG_POOL_STATE " not found");
      return grub_errno;
    }
  grub_dprintf ("zfs", "check 3 passed\n");

  if (pool_state == POOL_STATE_DESTROYED)
    {
      grub_free (nvlist);
      return grub_error (GRUB_ERR_BAD_FS, "zpool is marked as destroyed");
    }
  grub_dprintf ("zfs", "check 4 passed\n");

  found = grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_POOL_TXG, &txg);
  if (!found)
    {
      grub_free (nvlist);
      if (! grub_errno)
	grub_error (GRUB_ERR_BAD_FS, ZPOOL_CONFIG_POOL_TXG " not found");
      return grub_errno;
    }
  grub_dprintf ("zfs", "check 6 passed\n");

  /* not an active device */
  if (txg == 0)
    {
      grub_free (nvlist);
      return grub_error (GRUB_ERR_BAD_FS, "zpool isn't active");
    }
  grub_dprintf ("zfs", "check 7 passed\n");

  found = grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_VERSION,
					 &version);
  if (! found)
    {
      grub_free (nvlist);
      if (! grub_errno)
	grub_error (GRUB_ERR_BAD_FS, ZPOOL_CONFIG_VERSION " not found");
      return grub_errno;
    }
  grub_dprintf ("zfs", "check 8 passed\n");

  if (version > SPA_VERSION)
    {
      grub_free (nvlist);
      return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			 "too new version %llu > %llu",
			 (unsigned long long) version,
			 (unsigned long long) SPA_VERSION);
    }
  grub_dprintf ("zfs", "check 9 passed\n");
#if 0
  if (nvlist_lookup_value (nvlist, ZPOOL_CONFIG_VDEV_TREE, &nv,
			   DATA_TYPE_NVLIST, NULL))
    {
      grub_free (vdev);
      return (GRUB_ERR_BAD_FS);
    }
  grub_dprintf ("zfs", "check 10 passed\n");
#endif

  found = grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_GUID, &diskguid);
  if (! found)
    {
      grub_free (nvlist);
      if (! grub_errno)
	grub_error (GRUB_ERR_BAD_FS, ZPOOL_CONFIG_GUID " not found");
      return grub_errno;
    }
  grub_dprintf ("zfs", "check 11 passed\n");

  grub_free (nvlist);

  return GRUB_ERR_NONE;
}

static void
zfs_unmount (struct grub_zfs_data *data)
{
  grub_free (data->dnode_buf);
  grub_free (data->dnode_mdn);
  grub_free (data->file_buf);
  grub_free (data);
}

/*
 * zfs_mount() locates a valid uberblock of the root pool and read in its MOS
 * to the memory address MOS.
 *
 */
static struct grub_zfs_data *
zfs_mount (grub_device_t dev)
{
  struct grub_zfs_data *data = 0;
  int label = 0;
  uberblock_phys_t *ub_array, *ubbest = NULL;
  vdev_boot_header_t *bh;
  objset_phys_t *osp = 0;
  grub_size_t ospsize;
  grub_err_t err;
  int vdevnum;

  if (! dev->disk)
    {
      grub_error (GRUB_ERR_BAD_DEVICE, "not a disk");
      return 0;
    }

  data = grub_malloc (sizeof (*data));
  if (!data)
    return 0;
  grub_memset (data, 0, sizeof (*data));
#if 0
  /* if it's our first time here, zero the best uberblock out */
  if (data->best_drive == 0 && data->best_part == 0 && find_best_root)
    grub_memset (&current_uberblock, 0, sizeof (uberblock_t));
#endif

  data->disk = dev->disk;

  ub_array = grub_malloc (VDEV_UBERBLOCK_RING);
  if (!ub_array)
    {
      zfs_unmount (data);
      return 0;
    }

  bh = grub_malloc (VDEV_BOOT_HEADER_SIZE);
  if (!bh)
    {
      zfs_unmount (data);
      grub_free (ub_array);
      return 0;
    }

  vdevnum = VDEV_LABELS;

  /* Don't check back labels on CDROM.  */
  if (grub_disk_get_size (dev->disk) == GRUB_DISK_SIZE_UNKNOWN)
    vdevnum = VDEV_LABELS / 2;

  for (label = 0; ubbest == NULL && label < vdevnum; label++)
    {
      grub_zfs_endian_t ub_endian = UNKNOWN_ENDIAN;
      grub_dprintf ("zfs", "label %d\n", label);

      data->vdev_phys_sector
	= label * (sizeof (vdev_label_t) >> SPA_MINBLOCKSHIFT)
	+ ((VDEV_SKIP_SIZE + VDEV_BOOT_HEADER_SIZE) >> SPA_MINBLOCKSHIFT)
	+ (label < VDEV_LABELS / 2 ? 0 : grub_disk_get_size (dev->disk)
	   - VDEV_LABELS * (sizeof (vdev_label_t) >> SPA_MINBLOCKSHIFT));

      /* Read in the uberblock ring (128K). */
      err = grub_disk_read (data->disk, data->vdev_phys_sector
			    + (VDEV_PHYS_SIZE >> SPA_MINBLOCKSHIFT),
			    0, VDEV_UBERBLOCK_RING, (char *) ub_array);
      if (err)
	{
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}
      grub_dprintf ("zfs", "label ok %d\n", label);

      ubbest = find_bestub (ub_array, data->vdev_phys_sector);
      if (!ubbest)
	{
	  grub_dprintf ("zfs", "No uberblock found\n");
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}
      ub_endian = (grub_zfs_to_cpu64 (ubbest->ubp_uberblock.ub_magic, 
				     LITTLE_ENDIAN) == UBERBLOCK_MAGIC 
		   ? LITTLE_ENDIAN : BIG_ENDIAN);
      err = zio_read (&ubbest->ubp_uberblock.ub_rootbp, 
		      ub_endian,
		      (void **) &osp, &ospsize, data);
      if (err)
	{
	  grub_dprintf ("zfs", "couldn't zio_read\n"); 
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}

      if (ospsize < OBJSET_PHYS_SIZE_V14)
	{
	  grub_dprintf ("zfs", "osp too small\n"); 
	  grub_free (osp);
	  continue;
	}
      grub_dprintf ("zfs", "ubbest %p\n", ubbest);

      err = check_pool_label (data);
      if (err)
	{
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}
#if 0
      if (find_best_root &&
	  vdev_uberblock_compare (&ubbest->ubp_uberblock,
				  &(current_uberblock)) <= 0)
	continue;
#endif
      /* Got the MOS. Save it at the memory addr MOS. */
      grub_memmove (&(data->mos.dn), &osp->os_meta_dnode, DNODE_SIZE);
      data->mos.endian = (grub_zfs_to_cpu64 (ubbest->ubp_uberblock.ub_rootbp.blk_prop, ub_endian) >> 63) & 1;
      grub_memmove (&(data->current_uberblock),
		    &ubbest->ubp_uberblock, sizeof (uberblock_t));
      grub_free (ub_array);
      grub_free (bh);
      grub_free (osp);
      return data;  
    }
  grub_error (GRUB_ERR_BAD_FS, "couldn't find a valid label");
  zfs_unmount (data);
  grub_free (ub_array);
  grub_free (bh);
  grub_free (osp);

  return 0;
}

grub_err_t
grub_zfs_fetch_nvlist (grub_device_t dev, char **nvlist)
{
  struct grub_zfs_data *zfs;
  grub_err_t err;

  zfs = zfs_mount (dev);
  if (!zfs)
    return grub_errno;
  err = zfs_fetch_nvlist (zfs, nvlist);
  zfs_unmount (zfs);
  return err;
}

static grub_err_t 
zfs_label (grub_device_t device, char **label)
{
  char *nvlist;
  grub_err_t err;
  struct grub_zfs_data *data;

  data = zfs_mount (device);
  if (! data)
    return grub_errno;

  err = zfs_fetch_nvlist (data, &nvlist);
  if (err)      
    {
      zfs_unmount (data);
      return err;
    }

  *label = grub_zfs_nvlist_lookup_string (nvlist, ZPOOL_CONFIG_POOL_NAME);
  grub_free (nvlist);
  zfs_unmount (data);
  return grub_errno;
}

static grub_err_t 
zfs_uuid (grub_device_t device, char **uuid)
{
  char *nvlist;
  int found;
  struct grub_zfs_data *data;
  grub_uint64_t guid;
  grub_err_t err;

  *uuid = 0;

  data = zfs_mount (device);
  if (! data)
    return grub_errno;

  err = zfs_fetch_nvlist (data, &nvlist);
  if (err)
    {
      zfs_unmount (data);
      return err;
    }

  found = grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_POOL_GUID, &guid);
  if (! found)
    return grub_errno;
  grub_free (nvlist);
  *uuid = grub_xasprintf ("%016llx", (long long unsigned) guid);
  zfs_unmount (data);
  if (! *uuid)
    return grub_errno;
  return GRUB_ERR_NONE;
}

/*
 * zfs_open() locates a file in the rootpool by following the
 * MOS and places the dnode of the file in the memory address DNODE.
 */
static grub_err_t
grub_zfs_open (struct grub_file *file, const char *fsfilename)
{
  struct grub_zfs_data *data;
  grub_err_t err;
  int isfs;

  data = zfs_mount (file->device);
  if (! data)
    return grub_errno;

  err = dnode_get_fullpath (fsfilename, &(data->mdn), 0,
			    &(data->dnode), &isfs, data);
  if (err)
    {
      zfs_unmount (data);
      return err;
    }

  if (isfs)
    {
      zfs_unmount (data);
      return grub_error (GRUB_ERR_FILE_NOT_FOUND, "Missing @ or / separator");
    }

  /* We found the dnode for this file. Verify if it is a plain file. */
  if (data->dnode.dn.dn_type != DMU_OT_PLAIN_FILE_CONTENTS) 
    {
      zfs_unmount (data);
      return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a file");
    }

  /* get the file size and set the file position to 0 */

  /*
   * For DMU_OT_SA we will need to locate the SIZE attribute
   * attribute, which could be either in the bonus buffer
   * or the "spill" block.
   */
  if (data->dnode.dn.dn_bonustype == DMU_OT_SA)
    {
      sa_hdr_phys_t *sahdrp;
      int hdrsize;

      if (data->dnode.dn.dn_bonuslen != 0)
	{
	  sahdrp = (sa_hdr_phys_t *) DN_BONUS (&data->dnode.dn);
	}
      else if (data->dnode.dn.dn_flags & DNODE_FLAG_SPILL_BLKPTR)
	{
	  blkptr_t *bp = &data->dnode.dn.dn_spill;

	  err = zio_read (bp, data->dnode.endian, (void **) &sahdrp, NULL, data);
	  if (err)
	    return err;
	}
      else
	{
	  return grub_error (GRUB_ERR_BAD_FS, "filesystem is corrupt");
	}

      hdrsize = SA_HDR_SIZE (sahdrp);
      file->size = *(grub_uint64_t *) ((char *) sahdrp + hdrsize + SA_SIZE_OFFSET);
    }
  else
    {
      file->size = grub_zfs_to_cpu64 (((znode_phys_t *) DN_BONUS (&data->dnode.dn))->zp_size, data->dnode.endian);
    }

  file->data = data;
  file->offset = 0;

#ifndef GRUB_UTIL
  grub_dl_ref (my_mod);
#endif

  return GRUB_ERR_NONE;
}

static grub_ssize_t
grub_zfs_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_zfs_data *data = (struct grub_zfs_data *) file->data;
  int blksz, movesize;
  grub_size_t length;
  grub_size_t read;
  grub_err_t err;

  if (data->file_buf == NULL)
    {
      data->file_buf = grub_malloc (SPA_MAXBLOCKSIZE);
      if (!data->file_buf)
	return -1;
      data->file_start = data->file_end = 0;
    }

  /*
   * If offset is in memory, move it into the buffer provided and return.
   */
  if (file->offset >= data->file_start
      && file->offset + len <= data->file_end)
    {
      grub_memmove (buf, data->file_buf + file->offset - data->file_start,
		    len);
      return len;
    }

  blksz = grub_zfs_to_cpu16 (data->dnode.dn.dn_datablkszsec, 
			     data->dnode.endian) << SPA_MINBLOCKSHIFT;

  /*
   * Entire Dnode is too big to fit into the space available.  We
   * will need to read it in chunks.  This could be optimized to
   * read in as large a chunk as there is space available, but for
   * now, this only reads in one data block at a time.
   */
  length = len;
  read = 0;
  while (length)
    {
      /*
       * Find requested blkid and the offset within that block.
       */
      grub_uint64_t blkid = grub_divmod64 (file->offset + read, blksz, 0);
      grub_free (data->file_buf);
      data->file_buf = 0;

      err = dmu_read (&(data->dnode), blkid, (void **) &(data->file_buf),
		      0, data);
      if (err)
	return -1;

      data->file_start = blkid * blksz;
      data->file_end = data->file_start + blksz;

      movesize = MIN (length, data->file_end - (int) file->offset - read);

      grub_memmove (buf, data->file_buf + file->offset + read
		    - data->file_start, movesize);
      buf += movesize;
      length -= movesize;
      read += movesize;
    }

  return len;
}

static grub_err_t
grub_zfs_close (grub_file_t file)
{
  zfs_unmount ((struct grub_zfs_data *) file->data);

#ifndef GRUB_UTIL
  grub_dl_unref (my_mod);
#endif

  return GRUB_ERR_NONE;
}

grub_err_t
grub_zfs_getmdnobj (grub_device_t dev, const char *fsfilename,
		    grub_uint64_t *mdnobj)
{
  struct grub_zfs_data *data;
  grub_err_t err;
  int isfs;

  data = zfs_mount (dev);
  if (! data)
    return grub_errno;

  err = dnode_get_fullpath (fsfilename, &(data->mdn), mdnobj,
			    &(data->dnode), &isfs, data);
  zfs_unmount (data);
  return err;
}

static void
fill_fs_info (struct grub_dirhook_info *info,
	      dnode_end_t mdn, struct grub_zfs_data *data)
{
  grub_err_t err;
  dnode_end_t dn;
  grub_uint64_t objnum;
  grub_uint64_t headobj;
  
  grub_memset (info, 0, sizeof (*info));
    
  info->dir = 1;
  
  if (mdn.dn.dn_type == DMU_OT_DSL_DIR)
    {
      headobj = grub_zfs_to_cpu64 (((dsl_dir_phys_t *) DN_BONUS (&mdn.dn))->dd_head_dataset_obj, mdn.endian);

      err = dnode_get (&(data->mos), headobj, DMU_OT_DSL_DATASET, &mdn, data);
      if (err)
	{
	  grub_dprintf ("zfs", "failed here\n");
	  return;
	}
    }
  make_mdn (&mdn, data);
  err = dnode_get (&mdn, MASTER_NODE_OBJ, DMU_OT_MASTER_NODE, 
		   &dn, data);
  if (err)
    {
      grub_dprintf ("zfs", "failed here\n");
      return;
    }
  
  err = zap_lookup (&dn, ZFS_ROOT_OBJ, &objnum, data);
  if (err)
    {
      grub_dprintf ("zfs", "failed here\n");
      return;
    }
  
  err = dnode_get (&mdn, objnum, 0, &dn, data);
  if (err)
    {
      grub_dprintf ("zfs", "failed here\n");
      return;
    }
  
  info->mtimeset = 1;
  info->mtime = grub_zfs_to_cpu64 (((znode_phys_t *) DN_BONUS (&dn.dn))->zp_mtime[0], dn.endian);
  return;
}

static grub_err_t
grub_zfs_dir (grub_device_t device, const char *path,
	      int (*hook) (const char *, const struct grub_dirhook_info *))
{
  struct grub_zfs_data *data;
  grub_err_t err;
  int isfs;
  auto int NESTED_FUNC_ATTR iterate_zap (const char *name, grub_uint64_t val);
  auto int NESTED_FUNC_ATTR iterate_zap_fs (const char *name, 
					    grub_uint64_t val);
  auto int NESTED_FUNC_ATTR iterate_zap_snap (const char *name, 
					      grub_uint64_t val);

  int NESTED_FUNC_ATTR iterate_zap (const char *name, grub_uint64_t val)
  {
    struct grub_dirhook_info info;
    dnode_end_t dn;
    grub_memset (&info, 0, sizeof (info));

    dnode_get (&(data->mdn), val, 0, &dn, data);
    info.mtimeset = 1;
    info.mtime = grub_zfs_to_cpu64 (((znode_phys_t *) DN_BONUS (&dn.dn))->zp_mtime[0], dn.endian);
    info.dir = (dn.dn.dn_type == DMU_OT_DIRECTORY_CONTENTS);
    grub_dprintf ("zfs", "type=%d, name=%s\n", 
		  (int)dn.dn.dn_type, (char *)name);
    return hook (name, &info);
  }

  int NESTED_FUNC_ATTR iterate_zap_fs (const char *name, grub_uint64_t val)
  {
    struct grub_dirhook_info info;
    dnode_end_t mdn;
    err = dnode_get (&(data->mos), val, 0, &mdn, data);
    if (err)
      return 0;
    if (mdn.dn.dn_type != DMU_OT_DSL_DIR)
      return 0;

    fill_fs_info (&info, mdn, data);
    return hook (name, &info);
  }
  int NESTED_FUNC_ATTR iterate_zap_snap (const char *name, grub_uint64_t val)
  {
    struct grub_dirhook_info info;
    char *name2;
    int ret;
    dnode_end_t mdn;

    err = dnode_get (&(data->mos), val, 0, &mdn, data);
    if (err)
      return 0;

    if (mdn.dn.dn_type != DMU_OT_DSL_DATASET)
      return 0;

    fill_fs_info (&info, mdn, data);

    name2 = grub_malloc (grub_strlen (name) + 2);
    name2[0] = '@';
    grub_memcpy (name2 + 1, name, grub_strlen (name) + 1);
    ret = hook (name2, &info);
    grub_free (name2);
    return ret;
  }

  data = zfs_mount (device);
  if (! data)
    return grub_errno;
  err = dnode_get_fullpath (path, &(data->mdn), 0, &(data->dnode), &isfs, data);
  if (err)
    {
      zfs_unmount (data);
      return err;
    }
  if (isfs)
    {
      grub_uint64_t childobj, headobj; 
      grub_uint64_t snapobj;
      dnode_end_t dn;
      struct grub_dirhook_info info;

      fill_fs_info (&info, data->dnode, data);
      hook ("@", &info);
      
      childobj = grub_zfs_to_cpu64 (((dsl_dir_phys_t *) DN_BONUS (&data->dnode.dn))->dd_child_dir_zapobj, data->dnode.endian);
      headobj = grub_zfs_to_cpu64 (((dsl_dir_phys_t *) DN_BONUS (&data->dnode.dn))->dd_head_dataset_obj, data->dnode.endian);
      err = dnode_get (&(data->mos), childobj,
		       DMU_OT_DSL_DIR_CHILD_MAP, &dn, data);
      if (err)
	{
	  zfs_unmount (data);
	  return err;
	}

      zap_iterate (&dn, iterate_zap_fs, data);
      
      err = dnode_get (&(data->mos), headobj, DMU_OT_DSL_DATASET, &dn, data);
      if (err)
	{
	  zfs_unmount (data);
	  return err;
	}

      snapobj = grub_zfs_to_cpu64 (((dsl_dataset_phys_t *) DN_BONUS (&dn.dn))->ds_snapnames_zapobj, dn.endian);

      err = dnode_get (&(data->mos), snapobj,
		       DMU_OT_DSL_DS_SNAP_MAP, &dn, data);
      if (err)
	{
	  zfs_unmount (data);
	  return err;
	}

      zap_iterate (&dn, iterate_zap_snap, data);
    }
  else
    {
      if (data->dnode.dn.dn_type != DMU_OT_DIRECTORY_CONTENTS)
	{
	  zfs_unmount (data);
	  return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");
	}
      zap_iterate (&(data->dnode), iterate_zap, data);
    }
  zfs_unmount (data);
  return grub_errno;
}

static struct grub_fs grub_zfs_fs = {
  .name = "zfs",
  .dir = grub_zfs_dir,
  .open = grub_zfs_open,
  .read = grub_zfs_read,
  .close = grub_zfs_close,
  .label = zfs_label,
  .uuid = zfs_uuid,
  .mtime = 0,
  .next = 0
};

GRUB_MOD_INIT (zfs)
{
  grub_fs_register (&grub_zfs_fs);
#ifndef GRUB_UTIL
  my_mod = mod;
#endif
}

GRUB_MOD_FINI (zfs)
{
  grub_fs_unregister (&grub_zfs_fs);
}
