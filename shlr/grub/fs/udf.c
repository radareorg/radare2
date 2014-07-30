/* udf.c - Universal Disk Format filesystem.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2008,2009  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
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

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/fshelp.h>
#include <grub/charset.h>

#define GRUB_UDF_MAX_PDS		2
#define GRUB_UDF_MAX_PMS		6

#define U16				grub_le_to_cpu16
#define U32				grub_le_to_cpu32
#define U64				grub_le_to_cpu64

#define GRUB_UDF_LOG2_BLKSZ		2
#define GRUB_UDF_BLKSZ			2048

#define GRUB_UDF_TAG_IDENT_PVD		0x0001
#define GRUB_UDF_TAG_IDENT_AVDP		0x0002
#define GRUB_UDF_TAG_IDENT_VDP		0x0003
#define GRUB_UDF_TAG_IDENT_IUVD		0x0004
#define GRUB_UDF_TAG_IDENT_PD		0x0005
#define GRUB_UDF_TAG_IDENT_LVD		0x0006
#define GRUB_UDF_TAG_IDENT_USD		0x0007
#define GRUB_UDF_TAG_IDENT_TD		0x0008
#define GRUB_UDF_TAG_IDENT_LVID		0x0009

#define GRUB_UDF_TAG_IDENT_FSD		0x0100
#define GRUB_UDF_TAG_IDENT_FID		0x0101
#define GRUB_UDF_TAG_IDENT_AED		0x0102
#define GRUB_UDF_TAG_IDENT_IE		0x0103
#define GRUB_UDF_TAG_IDENT_TE		0x0104
#define GRUB_UDF_TAG_IDENT_FE		0x0105
#define GRUB_UDF_TAG_IDENT_EAHD		0x0106
#define GRUB_UDF_TAG_IDENT_USE		0x0107
#define GRUB_UDF_TAG_IDENT_SBD		0x0108
#define GRUB_UDF_TAG_IDENT_PIE		0x0109
#define GRUB_UDF_TAG_IDENT_EFE		0x010A

#define GRUB_UDF_ICBTAG_TYPE_UNDEF	0x00
#define GRUB_UDF_ICBTAG_TYPE_USE	0x01
#define GRUB_UDF_ICBTAG_TYPE_PIE	0x02
#define GRUB_UDF_ICBTAG_TYPE_IE		0x03
#define GRUB_UDF_ICBTAG_TYPE_DIRECTORY	0x04
#define GRUB_UDF_ICBTAG_TYPE_REGULAR	0x05
#define GRUB_UDF_ICBTAG_TYPE_BLOCK	0x06
#define GRUB_UDF_ICBTAG_TYPE_CHAR	0x07
#define GRUB_UDF_ICBTAG_TYPE_EA		0x08
#define GRUB_UDF_ICBTAG_TYPE_FIFO	0x09
#define GRUB_UDF_ICBTAG_TYPE_SOCKET	0x0A
#define GRUB_UDF_ICBTAG_TYPE_TE		0x0B
#define GRUB_UDF_ICBTAG_TYPE_SYMLINK	0x0C
#define GRUB_UDF_ICBTAG_TYPE_STREAMDIR	0x0D

#define GRUB_UDF_ICBTAG_FLAG_AD_MASK	0x0007
#define GRUB_UDF_ICBTAG_FLAG_AD_SHORT	0x0000
#define GRUB_UDF_ICBTAG_FLAG_AD_LONG	0x0001
#define GRUB_UDF_ICBTAG_FLAG_AD_EXT	0x0002
#define GRUB_UDF_ICBTAG_FLAG_AD_IN_ICB	0x0003

#define GRUB_UDF_EXT_NORMAL		0x00000000
#define GRUB_UDF_EXT_NREC_ALLOC		0x40000000
#define GRUB_UDF_EXT_NREC_NALLOC	0x80000000
#define GRUB_UDF_EXT_MASK		0xC0000000

#define GRUB_UDF_FID_CHAR_HIDDEN	0x01
#define GRUB_UDF_FID_CHAR_DIRECTORY	0x02
#define GRUB_UDF_FID_CHAR_DELETED	0x04
#define GRUB_UDF_FID_CHAR_PARENT	0x08
#define GRUB_UDF_FID_CHAR_METADATA	0x10

#define GRUB_UDF_STD_IDENT_BEA01	"BEA01"
#define GRUB_UDF_STD_IDENT_BOOT2	"BOOT2"
#define GRUB_UDF_STD_IDENT_CD001	"CD001"
#define GRUB_UDF_STD_IDENT_CDW02	"CDW02"
#define GRUB_UDF_STD_IDENT_NSR02	"NSR02"
#define GRUB_UDF_STD_IDENT_NSR03	"NSR03"
#define GRUB_UDF_STD_IDENT_TEA01	"TEA01"

#define GRUB_UDF_CHARSPEC_TYPE_CS0	0x00
#define GRUB_UDF_CHARSPEC_TYPE_CS1	0x01
#define GRUB_UDF_CHARSPEC_TYPE_CS2	0x02
#define GRUB_UDF_CHARSPEC_TYPE_CS3	0x03
#define GRUB_UDF_CHARSPEC_TYPE_CS4	0x04
#define GRUB_UDF_CHARSPEC_TYPE_CS5	0x05
#define GRUB_UDF_CHARSPEC_TYPE_CS6	0x06
#define GRUB_UDF_CHARSPEC_TYPE_CS7	0x07
#define GRUB_UDF_CHARSPEC_TYPE_CS8	0x08

#define GRUB_UDF_PARTMAP_TYPE_1		1
#define GRUB_UDF_PARTMAP_TYPE_2		2

struct grub_udf_lb_addr
{
  grub_uint32_t block_num;
  grub_uint16_t part_ref;
} __attribute__ ((packed));

struct grub_udf_short_ad
{
  grub_uint32_t length;
  grub_uint32_t position;
} __attribute__ ((packed));

struct grub_udf_long_ad
{
  grub_uint32_t length;
  struct grub_udf_lb_addr block;
  grub_uint8_t imp_use[6];
} __attribute__ ((packed));

struct grub_udf_extent_ad
{
  grub_uint32_t length;
  grub_uint32_t start;
} __attribute__ ((packed));

struct grub_udf_charspec
{
  grub_uint8_t charset_type;
  grub_uint8_t charset_info[63];
} __attribute__ ((packed));

struct grub_udf_timestamp
{
  grub_uint16_t type_and_timezone;
  grub_uint16_t year;
  grub_uint8_t month;
  grub_uint8_t day;
  grub_uint8_t hour;
  grub_uint8_t minute;
  grub_uint8_t second;
  grub_uint8_t centi_seconds;
  grub_uint8_t hundreds_of_micro_seconds;
  grub_uint8_t micro_seconds;
} __attribute__ ((packed));

struct grub_udf_regid
{
  grub_uint8_t flags;
  grub_uint8_t ident[23];
  grub_uint8_t ident_suffix[8];
} __attribute__ ((packed));

struct grub_udf_tag
{
  grub_uint16_t tag_ident;
  grub_uint16_t desc_version;
  grub_uint8_t tag_checksum;
  grub_uint8_t reserved;
  grub_uint16_t tag_serial_number;
  grub_uint16_t desc_crc;
  grub_uint16_t desc_crc_length;
  grub_uint32_t tag_location;
} __attribute__ ((packed));

struct grub_udf_fileset
{
  struct grub_udf_tag tag;
  struct grub_udf_timestamp datetime;
  grub_uint16_t interchange_level;
  grub_uint16_t max_interchange_level;
  grub_uint32_t charset_list;
  grub_uint32_t max_charset_list;
  grub_uint32_t fileset_num;
  grub_uint32_t fileset_desc_num;
  struct grub_udf_charspec vol_charset;
  grub_uint8_t vol_ident[128];
  struct grub_udf_charspec fileset_charset;
  grub_uint8_t fileset_ident[32];
  grub_uint8_t copyright_file_ident[32];
  grub_uint8_t abstract_file_ident[32];
  struct grub_udf_long_ad root_icb;
  struct grub_udf_regid domain_ident;
  struct grub_udf_long_ad next_ext;
  struct grub_udf_long_ad streamdir_icb;
} __attribute__ ((packed));

struct grub_udf_icbtag
{
  grub_uint32_t prior_recorded_num_direct_entries;
  grub_uint16_t strategy_type;
  grub_uint16_t strategy_parameter;
  grub_uint16_t num_entries;
  grub_uint8_t reserved;
  grub_uint8_t file_type;
  struct grub_udf_lb_addr parent_idb;
  grub_uint16_t flags;
} __attribute__ ((packed));

struct grub_udf_file_ident
{
  struct grub_udf_tag tag;
  grub_uint16_t version_num;
  grub_uint8_t characteristics;
  grub_uint8_t file_ident_length;
  struct grub_udf_long_ad icb;
  grub_uint16_t imp_use_length;
} __attribute__ ((packed));

struct grub_udf_file_entry
{
  struct grub_udf_tag tag;
  struct grub_udf_icbtag icbtag;
  grub_uint32_t uid;
  grub_uint32_t gid;
  grub_uint32_t permissions;
  grub_uint16_t link_count;
  grub_uint8_t record_format;
  grub_uint8_t record_display_attr;
  grub_uint32_t record_length;
  grub_uint64_t file_size;
  grub_uint64_t blocks_recorded;
  struct grub_udf_timestamp access_time;
  struct grub_udf_timestamp modification_time;
  struct grub_udf_timestamp attr_time;
  grub_uint32_t checkpoint;
  struct grub_udf_long_ad extended_attr_idb;
  struct grub_udf_regid imp_ident;
  grub_uint64_t unique_id;
  grub_uint32_t ext_attr_length;
  grub_uint32_t alloc_descs_length;
  grub_uint8_t ext_attr[1872];
} __attribute__ ((packed));

struct grub_udf_extended_file_entry
{
  struct grub_udf_tag tag;
  struct grub_udf_icbtag icbtag;
  grub_uint32_t uid;
  grub_uint32_t gid;
  grub_uint32_t permissions;
  grub_uint16_t link_count;
  grub_uint8_t record_format;
  grub_uint8_t record_display_attr;
  grub_uint32_t record_length;
  grub_uint64_t file_size;
  grub_uint64_t object_size;
  grub_uint64_t blocks_recorded;
  struct grub_udf_timestamp access_time;
  struct grub_udf_timestamp modification_time;
  struct grub_udf_timestamp create_time;
  struct grub_udf_timestamp attr_time;
  grub_uint32_t checkpoint;
  grub_uint32_t reserved;
  struct grub_udf_long_ad extended_attr_icb;
  struct grub_udf_long_ad streamdir_icb;
  struct grub_udf_regid imp_ident;
  grub_uint64_t unique_id;
  grub_uint32_t ext_attr_length;
  grub_uint32_t alloc_descs_length;
  grub_uint8_t ext_attr[1832];
} __attribute__ ((packed));

struct grub_udf_vrs
{
  grub_uint8_t type;
  grub_uint8_t magic[5];
  grub_uint8_t version;
} __attribute__ ((packed));

struct grub_udf_avdp
{
  struct grub_udf_tag tag;
  struct grub_udf_extent_ad vds;
} __attribute__ ((packed));

struct grub_udf_pd
{
  struct grub_udf_tag tag;
  grub_uint32_t seq_num;
  grub_uint16_t flags;
  grub_uint16_t part_num;
  struct grub_udf_regid contents;
  grub_uint8_t contents_use[128];
  grub_uint32_t access_type;
  grub_uint32_t start;
  grub_uint32_t length;
} __attribute__ ((packed));

struct grub_udf_partmap
{
  grub_uint8_t type;
  grub_uint8_t length;
  union
  {
    struct
    {
      grub_uint16_t seq_num;
      grub_uint16_t part_num;
    } type1;

    struct
    {
      grub_uint8_t ident[62];
    } type2;
  };
};

struct grub_udf_lvd
{
  struct grub_udf_tag tag;
  grub_uint32_t seq_num;
  struct grub_udf_charspec charset;
  grub_uint8_t ident[128];
  grub_uint32_t bsize;
  struct grub_udf_regid domain_ident;
  struct grub_udf_long_ad root_fileset;
  grub_uint32_t map_table_length;
  grub_uint32_t num_part_maps;
  struct grub_udf_regid imp_ident;
  grub_uint8_t imp_use[128];
  struct grub_udf_extent_ad integrity_seq_ext;
  grub_uint8_t part_maps[1608];
} __attribute__ ((packed));

struct grub_udf_data
{
  grub_disk_t disk;
  struct grub_udf_lvd lvd;
  struct grub_udf_pd pds[GRUB_UDF_MAX_PDS];
  struct grub_udf_partmap *pms[GRUB_UDF_MAX_PMS];
  struct grub_udf_long_ad root_icb;
  int npd, npm;
};

struct grub_fshelp_node
{
  struct grub_udf_data *data;
  union
  {
    struct grub_udf_file_entry fe;
    struct grub_udf_extended_file_entry efe;
  };
  int part_ref;
};

static grub_dl_t my_mod;

static grub_uint32_t
grub_udf_get_block (struct grub_udf_data *data,
		    grub_uint16_t part_ref, grub_uint32_t block)
{
  part_ref = U16 (part_ref);

  if (part_ref >= data->npm)
    {
      grub_error (GRUB_ERR_BAD_FS, "invalid part ref");
      return 0;
    }

  return (U32 (data->pds[data->pms[part_ref]->type1.part_num].start)
          + U32 (block));
}

static grub_err_t
grub_udf_read_icb (struct grub_udf_data *data,
		   struct grub_udf_long_ad *icb,
		   struct grub_fshelp_node *node)
{
  grub_uint32_t block;

  block = grub_udf_get_block (data,
			      icb->block.part_ref,
                              icb->block.block_num);

  if (grub_errno)
    return grub_errno;

  if (grub_disk_read (data->disk, block << GRUB_UDF_LOG2_BLKSZ, 0,
		      sizeof (struct grub_udf_file_entry),
		      &node->fe))
    return grub_errno;

  if ((U16 (node->fe.tag.tag_ident) != GRUB_UDF_TAG_IDENT_FE) &&
      (U16 (node->fe.tag.tag_ident) != GRUB_UDF_TAG_IDENT_EFE))
    return grub_error (GRUB_ERR_BAD_FS, "invalid fe/efe descriptor");

  node->part_ref = icb->block.part_ref;
  node->data = data;
  return 0;
}

static grub_disk_addr_t
grub_udf_read_block (grub_fshelp_node_t node, grub_disk_addr_t fileblock)
{
  char *ptr;
  int len;
  grub_disk_addr_t filebytes;

  if (U16 (node->fe.tag.tag_ident) == GRUB_UDF_TAG_IDENT_FE)
    {
      ptr = (char *) &node->fe.ext_attr[0] + U32 (node->fe.ext_attr_length);
      len = U32 (node->fe.alloc_descs_length);
    }
  else
    {
      ptr = (char *) &node->efe.ext_attr[0] + U32 (node->efe.ext_attr_length);
      len = U32 (node->efe.alloc_descs_length);
    }

  if ((U16 (node->fe.icbtag.flags) & GRUB_UDF_ICBTAG_FLAG_AD_MASK)
      == GRUB_UDF_ICBTAG_FLAG_AD_SHORT)
    {
      struct grub_udf_short_ad *ad = (struct grub_udf_short_ad *) ptr;

      len /= sizeof (struct grub_udf_short_ad);
      filebytes = fileblock * GRUB_UDF_BLKSZ;
      while (len > 0)
	{
	  if (filebytes < U32 (ad->length))
	    return ((U32 (ad->position) & GRUB_UDF_EXT_MASK) ? 0 :
                    (grub_udf_get_block (node->data,
                                         node->part_ref,
                                         ad->position)
                     + (filebytes / GRUB_UDF_BLKSZ)));

	  filebytes -= U32 (ad->length);
	  ad++;
	  len--;
	}
    }
  else
    {
      struct grub_udf_long_ad *ad = (struct grub_udf_long_ad *) ptr;

      len /= sizeof (struct grub_udf_long_ad);
      filebytes = fileblock * GRUB_UDF_BLKSZ;
      while (len > 0)
	{
	  if (filebytes < U32 (ad->length))
	    return ((U32 (ad->block.block_num) & GRUB_UDF_EXT_MASK) ?  0 :
                    (grub_udf_get_block (node->data,
                                         ad->block.part_ref,
                                         ad->block.block_num)
		     + (filebytes / GRUB_UDF_BLKSZ)));

	  filebytes -= U32 (ad->length);
	  ad++;
	  len--;
	}
    }

  return 0;
}

static grub_ssize_t
grub_udf_read_file (grub_fshelp_node_t node,
		    void (*read_hook) (grub_disk_addr_t sector,
				       unsigned offset, unsigned length,
				       void *closure),
		    void *closure, int flags,
		    int pos, grub_size_t len, char *buf)
{
  switch (U16 (node->fe.icbtag.flags) & GRUB_UDF_ICBTAG_FLAG_AD_MASK)
    {
    case GRUB_UDF_ICBTAG_FLAG_AD_IN_ICB:
      {
	char *ptr;

	ptr = ((U16 (node->fe.tag.tag_ident) == GRUB_UDF_TAG_IDENT_FE) ?
	       ((char *) &node->fe.ext_attr[0]
                + U32 (node->fe.ext_attr_length)) :
	       ((char *) &node->efe.ext_attr[0]
                + U32 (node->efe.ext_attr_length)));

	grub_memcpy (buf, ptr + pos, len);

	return len;
      }

    case GRUB_UDF_ICBTAG_FLAG_AD_EXT:
      grub_error (GRUB_ERR_BAD_FS, "invalid extent type");
      return 0;
    }

  return  grub_fshelp_read_file (node->data->disk, node, read_hook, closure,
				 flags, pos, len, buf, grub_udf_read_block,
                                 U64 (node->fe.file_size),
                                 GRUB_UDF_LOG2_BLKSZ);
}

static int sblocklist[] = { 256, 512, 0 };

static struct grub_udf_data *
grub_udf_mount (grub_disk_t disk)
{
  struct grub_udf_data *data = 0;
  struct grub_udf_fileset root_fs;
  int *sblklist = sblocklist;
  grub_uint32_t block;
  int i;

  data = grub_malloc (sizeof (struct grub_udf_data));
  if (!data)
    return 0;

  data->disk = disk;

  /* Search for Volume Recognition Sequence (VRS).  */
  for (block = 16;; block++)
    {
      struct grub_udf_vrs vrs;

      if (grub_disk_read (disk, block << GRUB_UDF_LOG2_BLKSZ, 0,
			  sizeof (struct grub_udf_vrs), &vrs))
	{
	  grub_error (GRUB_ERR_BAD_FS, "not an UDF filesystem");
	  goto fail;
	}

      if ((!grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_NSR03, 5)) ||
	  (!grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_NSR02, 5)))
	break;

      if ((grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_BEA01, 5)) &&
	  (grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_BOOT2, 5)) &&
	  (grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_CD001, 5)) &&
	  (grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_CDW02, 5)) &&
	  (grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_TEA01, 5)))
	{
	  grub_error (GRUB_ERR_BAD_FS, "not an UDF filesystem");
	  goto fail;
	}
    }

  /* Search for Anchor Volume Descriptor Pointer (AVDP).  */
  while (1)
    {
      struct grub_udf_avdp avdp;

      if (grub_disk_read (disk, *sblklist << GRUB_UDF_LOG2_BLKSZ, 0,
			  sizeof (struct grub_udf_avdp), &avdp))
	{
	  grub_error (GRUB_ERR_BAD_FS, "not an UDF filesystem");
	  goto fail;
	}

      if (U16 (avdp.tag.tag_ident) == GRUB_UDF_TAG_IDENT_AVDP)
	{
	  block = U32 (avdp.vds.start);
	  break;
	}

      sblklist++;
      if (*sblklist == 0)
	{
	  grub_error (GRUB_ERR_BAD_FS, "not an UDF filesystem");
	  goto fail;
	}
    }

  data->npd = data->npm = 0;
  /* Locate Partition Descriptor (PD) and Logical Volume Descriptor (LVD).  */
  while (1)
    {
      struct grub_udf_tag tag;

      if (grub_disk_read (disk, block << GRUB_UDF_LOG2_BLKSZ, 0,
			  sizeof (struct grub_udf_tag), &tag))
	{
	  grub_error (GRUB_ERR_BAD_FS, "not an UDF filesystem");
	  goto fail;
	}

      tag.tag_ident = U16 (tag.tag_ident);
      if (tag.tag_ident == GRUB_UDF_TAG_IDENT_PD)
	{
	  if (data->npd >= GRUB_UDF_MAX_PDS)
	    {
	      grub_error (GRUB_ERR_BAD_FS, "too many PDs");
	      goto fail;
	    }

	  if (grub_disk_read (disk, block << GRUB_UDF_LOG2_BLKSZ, 0,
			      sizeof (struct grub_udf_pd),
			      &data->pds[data->npd]))
	    {
	      grub_error (GRUB_ERR_BAD_FS, "not an UDF filesystem");
	      goto fail;
	    }

	  data->npd++;
	}
      else if (tag.tag_ident == GRUB_UDF_TAG_IDENT_LVD)
	{
	  int k;

	  struct grub_udf_partmap *ppm;

	  if (grub_disk_read (disk, block << GRUB_UDF_LOG2_BLKSZ, 0,
			      sizeof (struct grub_udf_lvd),
			      &data->lvd))
	    {
	      grub_error (GRUB_ERR_BAD_FS, "not an UDF filesystem");
	      goto fail;
	    }

	  if (data->npm + U32 (data->lvd.num_part_maps) > GRUB_UDF_MAX_PMS)
	    {
	      grub_error (GRUB_ERR_BAD_FS, "too many partition maps");
	      goto fail;
	    }

	  ppm = (struct grub_udf_partmap *) &data->lvd.part_maps;
	  for (k = U32 (data->lvd.num_part_maps); k > 0; k--)
	    {
	      if (ppm->type != GRUB_UDF_PARTMAP_TYPE_1)
		{
		  grub_error (GRUB_ERR_BAD_FS, "partmap type not supported");
		  goto fail;
		}

	      data->pms[data->npm++] = ppm;
	      ppm = (struct grub_udf_partmap *) ((char *) ppm +
                                                 U32 (ppm->length));
	    }
	}
      else if (tag.tag_ident > GRUB_UDF_TAG_IDENT_TD)
	{
	  grub_error (GRUB_ERR_BAD_FS, "invalid tag ident");
	  goto fail;
	}
      else if (tag.tag_ident == GRUB_UDF_TAG_IDENT_TD)
	break;

      block++;
    }

  for (i = 0; i < data->npm; i++)
    {
      int j;

      for (j = 0; j < data->npd; j++)
	if (data->pms[i]->type1.part_num == data->pds[j].part_num)
	  {
	    data->pms[i]->type1.part_num = j;
	    break;
	  }

      if (j == data->npd)
	{
	  grub_error (GRUB_ERR_BAD_FS, "can\'t find PD");
	  goto fail;
	}
    }

  block = grub_udf_get_block (data,
			      data->lvd.root_fileset.block.part_ref,
			      data->lvd.root_fileset.block.block_num);

  if (grub_errno)
    goto fail;

  if (grub_disk_read (disk, block << GRUB_UDF_LOG2_BLKSZ, 0,
		      sizeof (struct grub_udf_fileset), &root_fs))
    {
      grub_error (GRUB_ERR_BAD_FS, "not an UDF filesystem");
      goto fail;
    }

  if (U16 (root_fs.tag.tag_ident) != GRUB_UDF_TAG_IDENT_FSD)
    {
      grub_error (GRUB_ERR_BAD_FS, "invalid fileset descriptor");
      goto fail;
    }

  data->root_icb = root_fs.root_icb;

  return data;

fail:
  grub_free (data);
  return 0;
}

static int
grub_udf_iterate_dir (grub_fshelp_node_t dir,
		      int (*hook) (const char *filename,
				   enum grub_fshelp_filetype filetype,
				   grub_fshelp_node_t node,
				   void *closure),
		      void *closure)
{
  grub_fshelp_node_t child;
  struct grub_udf_file_ident dirent;
  grub_uint32_t offset = 0;

  child = grub_malloc (sizeof (struct grub_fshelp_node));
  if (!child)
    return 0;

  /* The current directory is not stored.  */
  grub_memcpy ((char *) child, (char *) dir,
	       sizeof (struct grub_fshelp_node));

  if (hook (".", GRUB_FSHELP_DIR, child, closure))
    return 1;

  while (offset < U64 (dir->fe.file_size))
    {
      if (grub_udf_read_file (dir, 0, 0, 0, offset, sizeof (dirent),
			      (char *) &dirent) != sizeof (dirent))
	return 0;

      if (U16 (dirent.tag.tag_ident) != GRUB_UDF_TAG_IDENT_FID)
	{
	  grub_error (GRUB_ERR_BAD_FS, "invalid fid tag");
	  return 0;
	}

      child = grub_malloc (sizeof (struct grub_fshelp_node));
      if (!child)
	return 0;

      if (grub_udf_read_icb (dir->data, &dirent.icb, child))
	return 0;

      offset += sizeof (dirent) + U16 (dirent.imp_use_length);
      if (dirent.characteristics & GRUB_UDF_FID_CHAR_PARENT)
	{
	  /* This is the parent directory.  */
	  if (hook ("..", GRUB_FSHELP_DIR, child, closure))
	    return 1;
	}
      else
	{
	  enum grub_fshelp_filetype type;
	  grub_uint8_t raw[dirent.file_ident_length];
	  grub_uint16_t utf16[dirent.file_ident_length - 1];
	  grub_uint8_t filename[dirent.file_ident_length * 2];
	  grub_size_t utf16len = 0;

	  type = ((dirent.characteristics & GRUB_UDF_FID_CHAR_DIRECTORY) ?
		  (GRUB_FSHELP_DIR) : (GRUB_FSHELP_REG));

	  if ((grub_udf_read_file (dir, 0, 0, 0, offset,
				   dirent.file_ident_length,
				   (char *) raw))
	      != dirent.file_ident_length)
	    return 0;

	  if (raw[0] == 8)
	    {
	      unsigned i;
	      utf16len = dirent.file_ident_length - 1;
	      for (i = 0; i < utf16len; i++)
		utf16[i] = raw[i + 1];
	    }
	  if (raw[0] == 16)
	    {
	      unsigned i;
	      utf16len = (dirent.file_ident_length - 1) / 2;
	      for (i = 0; i < utf16len; i++)
		utf16[i] = (raw[2 * i + 1] << 8) | raw[2*i + 2];
	    }
	  if (raw[0] == 8 || raw[0] == 16)
	    {
	      *grub_utf16_to_utf8 (filename, utf16, utf16len) = '\0';

	      if (hook ((char *) filename, type, child, closure))
		return 1;
	    }
	}

      /* Align to dword boundary.  */
      offset = (offset + dirent.file_ident_length + 3) & (~3);
    }
  grub_free(child);
  return 0;
}

struct grub_udf_dir_closure
{
  int (*hook) (const char *filename,
	       const struct grub_dirhook_info *info,
	       void *closure);
  void *closure;
};

static int
iterate (const char *filename,
	 enum grub_fshelp_filetype filetype,
	 grub_fshelp_node_t node,
	 void *closure)
{
  struct grub_udf_dir_closure *c = closure;
  struct grub_dirhook_info info;
  grub_memset (&info, 0, sizeof (info));
  info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
  grub_free (node);
  return c->hook (filename, &info, c->closure);
}

static grub_err_t
grub_udf_dir (grub_device_t device, const char *path,
	      int (*hook) (const char *filename,
			   const struct grub_dirhook_info *info,
			   void *closure),
	      void *closure)
{
  struct grub_udf_data *data = 0;
  struct grub_fshelp_node rootnode;
  struct grub_fshelp_node *foundnode;
  struct grub_udf_dir_closure c;

  grub_dl_ref (my_mod);

  data = grub_udf_mount (device->disk);
  if (!data)
    goto fail;

  if (grub_udf_read_icb (data, &data->root_icb, &rootnode))
    goto fail;

  if (grub_fshelp_find_file (path, &rootnode,
			     &foundnode,
			     grub_udf_iterate_dir, 0, 0, GRUB_FSHELP_DIR))
    goto fail;

  if (hook) {
    c.hook = hook;
    c.closure = closure;
    grub_udf_iterate_dir (foundnode, iterate, &c);
  }

  if (foundnode != &rootnode)
    grub_free (foundnode);

fail:
  grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_err_t
grub_udf_open (struct grub_file *file, const char *name)
{
  struct grub_udf_data *data;
  struct grub_fshelp_node rootnode;
  struct grub_fshelp_node *foundnode;

  grub_dl_ref (my_mod);

  data = grub_udf_mount (file->device->disk);
  if (!data)
    goto fail;

  if (grub_udf_read_icb (data, &data->root_icb, &rootnode))
    goto fail;

  if (grub_fshelp_find_file (name, &rootnode,
			     &foundnode,
			     grub_udf_iterate_dir, 0, 0, GRUB_FSHELP_REG))
    goto fail;

  file->data = foundnode;
  file->offset = 0;
  file->size = U64 (foundnode->fe.file_size);

  return 0;

fail:
  grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;
}

static grub_ssize_t
grub_udf_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_fshelp_node *node = (struct grub_fshelp_node *) file->data;

  return grub_udf_read_file (node, file->read_hook, file->closure,
			     file->flags, file->offset, len, buf);
}

static grub_err_t
grub_udf_close (grub_file_t file)
{
  if (file->data)
    {
      struct grub_fshelp_node *node = (struct grub_fshelp_node *) file->data;

      grub_free (node->data);
      grub_free (node);
    }

  grub_dl_unref (my_mod);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_udf_label (grub_device_t device, char **label)
{
  struct grub_udf_data *data;
  data = grub_udf_mount (device->disk);

  if (data)
    {
      *label = grub_strdup ((char *) &data->lvd.ident[1]);
      grub_free (data);
    }
  else
    *label = 0;

  return grub_errno;
}

struct grub_fs grub_udf_fs = {
  .name = "udf",
  .dir = grub_udf_dir,
  .open = grub_udf_open,
  .read = grub_udf_read,
  .close = grub_udf_close,
  .label = grub_udf_label,
  .next = 0
};
