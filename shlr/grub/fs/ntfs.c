/* ntfs.c - NTFS filesystem */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2007,2008,2009 Free Software Foundation, Inc.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/fshelp.h>
#include <grub/ntfs.h>
#include <grub/charset.h>
#include <grub/partition.h>

GRUB_EXPORT(grub_ntfscomp_func);
GRUB_EXPORT(grub_ntfs_read_run_list);

static grub_dl_t my_mod;

ntfscomp_func_t grub_ntfscomp_func;

static grub_err_t
fixup (struct grub_ntfs_data *data, char *buf, int len, char *magic)
{
  int ss;
  char *pu;
  grub_uint16_t us;

  if (grub_memcmp (buf, magic, 4))
    return grub_error (GRUB_ERR_BAD_FS, "%s label not found", magic);

  ss = u16at (buf, 6) - 1;
  if (ss * (int) data->blocksize != len * GRUB_DISK_SECTOR_SIZE)
    return grub_error (GRUB_ERR_BAD_FS, "size not match",
		       ss * (int) data->blocksize,
		       len * GRUB_DISK_SECTOR_SIZE);
  pu = buf + u16at (buf, 4);
  us = u16at (pu, 0);
  buf -= 2;
  while (ss > 0)
    {
      buf += data->blocksize;
      pu += 2;
      if (u16at (buf, 0) != us)
	return grub_error (GRUB_ERR_BAD_FS, "fixup signature not match");
      v16at (buf, 0) = v16at (pu, 0);
      ss--;
    }

  return 0;
}

static grub_err_t read_mft (struct grub_ntfs_data *data, char *buf,
			    grub_uint32_t mftno, grub_uint32_t *sector);
static grub_err_t read_attr (struct grub_ntfs_attr *at, char *dest,
			     grub_disk_addr_t ofs, grub_size_t len,
			     int cached,
			     void (*read_hook) (grub_disk_addr_t sector,
						unsigned offset,
						unsigned length,
						void *closure),
			     void *closure, int flags);

static grub_err_t read_data (struct grub_ntfs_attr *at, char *pa, char *dest,
			     grub_disk_addr_t ofs, grub_size_t len,
			     int cached,
			     void (*read_hook) (grub_disk_addr_t sector,
						unsigned offset,
						unsigned length,
						void *closure),
			     void *closure, int flags);

static void
init_attr (struct grub_ntfs_attr *at, struct grub_ntfs_file *mft)
{
  at->mft = mft;
  at->flags = (mft == &mft->data->mmft) ? AF_MMFT : 0;
  at->attr_nxt = mft->buf + u16at (mft->buf, 0x14);
  at->attr_end = at->emft_buf = at->edat_buf = at->sbuf = NULL;
}

static void
free_attr (struct grub_ntfs_attr *at)
{
  grub_free (at->emft_buf);
  grub_free (at->edat_buf);
  grub_free (at->sbuf);
}

static char *
find_attr (struct grub_ntfs_attr *at, unsigned char attr)
{
  if (at->flags & AF_ALST)
    {
    retry:
      while (at->attr_nxt < at->attr_end)
	{
	  at->attr_cur = at->attr_nxt;
	  at->attr_nxt += u16at (at->attr_cur, 4);
	  if (((unsigned char) *at->attr_cur == attr) || (attr == 0))
	    {
	      char *new_pos;

	      if (at->flags & AF_MMFT)
		{
		  if ((grub_disk_read
		       (at->mft->data->disk, v32at (at->attr_cur, 0x10), 0,
			512, at->emft_buf))
		      ||
		      (grub_disk_read
		       (at->mft->data->disk, v32at (at->attr_cur, 0x14), 0,
			512, at->emft_buf + 512)))
		    return NULL;

		  if (fixup
		      (at->mft->data, at->emft_buf, at->mft->data->mft_size,
		       "FILE"))
		    return NULL;
		}
	      else
		{
		  if (read_mft (at->mft->data, at->emft_buf,
				u32at (at->attr_cur, 0x10), 0))
		    return NULL;
		}

	      new_pos = &at->emft_buf[u16at (at->emft_buf, 0x14)];
	      while ((unsigned char) *new_pos != 0xFF)
		{
		  if (((unsigned char) *new_pos ==
		       (unsigned char) *at->attr_cur)
		      && (u16at (new_pos, 0xE) == u16at (at->attr_cur, 0x18)))
		    {
		      return new_pos;
		    }
		  new_pos += u16at (new_pos, 4);
		}
	      grub_error (GRUB_ERR_BAD_FS,
			  "can\'t find 0x%X in attribute list",
			  (unsigned char) *at->attr_cur);
	      return NULL;
	    }
	}
      return NULL;
    }
  at->attr_cur = at->attr_nxt;
  while ((unsigned char) *at->attr_cur != 0xFF)
    {
      at->attr_nxt += u16at (at->attr_cur, 4);
      if ((unsigned char) *at->attr_cur == AT_ATTRIBUTE_LIST)
	at->attr_end = at->attr_cur;
      if (((unsigned char) *at->attr_cur == attr) || (attr == 0))
	return at->attr_cur;
      at->attr_cur = at->attr_nxt;
    }
  if (at->attr_end)
    {
      char *pa;

      at->emft_buf = grub_malloc (at->mft->data->mft_size << BLK_SHR);
      if (at->emft_buf == NULL)
	return NULL;

      pa = at->attr_end;
      if (pa[8])
	{
          int n;

          n = ((u32at (pa, 0x30) + GRUB_DISK_SECTOR_SIZE - 1)
               & (~(GRUB_DISK_SECTOR_SIZE - 1)));
	  at->attr_cur = at->attr_end;
	  at->edat_buf = grub_malloc (n);
	  if (!at->edat_buf)
	    return NULL;
	  if (read_data (at, pa, at->edat_buf, 0, n, 0, 0, 0, 0))
	    {
	      grub_error (GRUB_ERR_BAD_FS,
			  "fail to read non-resident attribute list");
	      return NULL;
	    }
	  at->attr_nxt = at->edat_buf;
	  at->attr_end = at->edat_buf + u32at (pa, 0x30);
	}
      else
	{
	  at->attr_nxt = at->attr_end + u16at (pa, 0x14);
	  at->attr_end = at->attr_end + u32at (pa, 4);
	}
      at->flags |= AF_ALST;
      while (at->attr_nxt < at->attr_end)
	{
	  if (((unsigned char) *at->attr_nxt == attr) || (attr == 0))
	    break;
	  at->attr_nxt += u16at (at->attr_nxt, 4);
	}
      if (at->attr_nxt >= at->attr_end)
	return NULL;

      if ((at->flags & AF_MMFT) && (attr == AT_DATA))
	{
	  at->flags |= AF_GPOS;
	  at->attr_cur = at->attr_nxt;
	  pa = at->attr_cur;
	  v32at (pa, 0x10) = at->mft->data->mft_start;
	  v32at (pa, 0x14) = at->mft->data->mft_start + 1;
	  pa = at->attr_nxt + u16at (pa, 4);
	  while (pa < at->attr_end)
	    {
	      if ((unsigned char) *pa != attr)
		break;
	      if (read_attr
		  (at, pa + 0x10,
		   u32at (pa, 0x10) * (at->mft->data->mft_size << BLK_SHR),
		   at->mft->data->mft_size << BLK_SHR, 0, 0, 0, 0))
		return NULL;
	      pa += u16at (pa, 4);
	    }
	  at->attr_nxt = at->attr_cur;
	  at->flags &= ~AF_GPOS;
	}
      goto retry;
    }
  return NULL;
}

static char *
locate_attr (struct grub_ntfs_attr *at, struct grub_ntfs_file *mft,
	     unsigned char attr)
{
  char *pa;

  init_attr (at, mft);
  if ((pa = find_attr (at, attr)) == NULL)
    return NULL;
  if ((at->flags & AF_ALST) == 0)
    {
      while (1)
	{
	  if ((pa = find_attr (at, attr)) == NULL)
	    break;
	  if (at->flags & AF_ALST)
	    return pa;
	}
      grub_errno = GRUB_ERR_NONE;
      free_attr (at);
      init_attr (at, mft);
      pa = find_attr (at, attr);
    }
  return pa;
}

static char *
read_run_data (char *run, int nn, grub_disk_addr_t * val, int sig)
{
  grub_disk_addr_t r, v;

  r = 0;
  v = 1;

  while (nn--)
    {
      r += v * (*(unsigned char *) (run++));
      v <<= 8;
    }

  if ((sig) && (r & (v >> 1)))
    r -= v;

  *val = r;
  return run;
}

grub_err_t
grub_ntfs_read_run_list (struct grub_ntfs_rlst * ctx)
{
  int c1, c2;
  grub_disk_addr_t val;
  char *run;

  run = ctx->cur_run;
retry:
  c1 = ((unsigned char) (*run) & 0xF);
  c2 = ((unsigned char) (*run) >> 4);
  if (!c1)
    {
      if ((ctx->attr) && (ctx->attr->flags & AF_ALST))
	{
	  void (*save_hook) (grub_disk_addr_t sector,
			     unsigned offset,
			     unsigned length,
			     void *closure);

	  save_hook = ctx->comp.disk->read_hook;
	  ctx->comp.disk->read_hook = 0;
	  run = find_attr (ctx->attr, (unsigned char) *ctx->attr->attr_cur);
	  ctx->comp.disk->read_hook = save_hook;
	  if (run)
	    {
	      if (run[8] == 0)
		return grub_error (GRUB_ERR_BAD_FS,
				   "$DATA should be non-resident");

	      run += u16at (run, 0x20);
	      ctx->curr_lcn = 0;
	      goto retry;
	    }
	}
      return grub_error (GRUB_ERR_BAD_FS, "run list overflown");
    }
  run = read_run_data (run + 1, c1, &val, 0);	/* length of current VCN */
  ctx->curr_vcn = ctx->next_vcn;
  ctx->next_vcn += val;
  run = read_run_data (run, c2, &val, 1);	/* offset to previous LCN */
  ctx->curr_lcn += val;
  if (val == 0)
    ctx->flags |= RF_BLNK;
  else
    ctx->flags &= ~RF_BLNK;
  ctx->cur_run = run;
  return 0;
}

static grub_disk_addr_t
grub_ntfs_read_block (grub_fshelp_node_t node, grub_disk_addr_t block)
{
  struct grub_ntfs_rlst *ctx;

  ctx = (struct grub_ntfs_rlst *) node;
  if (block >= ctx->next_vcn)
    {
      if (grub_ntfs_read_run_list (ctx))
	return -1;
      return ctx->curr_lcn;
    }
  else
    return (ctx->flags & RF_BLNK) ? 0 : (block -
					 ctx->curr_vcn + ctx->curr_lcn);
}

static grub_err_t
read_data (struct grub_ntfs_attr *at, char *pa, char *dest,
	   grub_disk_addr_t ofs, grub_size_t len, int cached,
	   void (*read_hook) (grub_disk_addr_t sector,
			      unsigned offset,
			      unsigned length,
			      void *closure),
	   void *closure, int flags)
{
  grub_disk_addr_t vcn;
  struct grub_ntfs_rlst cc, *ctx;

  if (len == 0)
    return 0;

  grub_memset (&cc, 0, sizeof (cc));
  ctx = &cc;
  ctx->attr = at;
  ctx->comp.spc = at->mft->data->spc;
  ctx->comp.disk = at->mft->data->disk;

  if (pa[8] == 0)
    {
      if (ofs + len > u32at (pa, 0x10))
	return grub_error (GRUB_ERR_BAD_FS, "read out of range");
      pa += u32at (pa, 0x14) + ofs;
      if (dest)
	grub_memcpy (dest, pa, len);
      if (read_hook)
	{
	  if ((pa >= at->mft->buf) && (pa < at->mft->buf + 512))
	    read_hook (at->mft->sector, pa - at->mft->buf, len, closure);
	  else if ((pa >= at->mft->buf + 512) && (pa < at->mft->buf + 1024))
	    read_hook (at->mft->sector + 1, pa - at->mft->buf - 512,
		       len, closure);
	}
      return 0;
    }

  if (u16at (pa, 0xC) & FLAG_COMPRESSED)
    ctx->flags |= RF_COMP;
  else
    ctx->flags &= ~RF_COMP;
  ctx->cur_run = pa + u16at (pa, 0x20);

  if (ctx->flags & RF_COMP)
    {
      if (!cached)
	return grub_error (GRUB_ERR_BAD_FS, "attribute can\'t be compressed");

      if (!dest)
	return grub_error (GRUB_ERR_BAD_FS, "can\'t get blocklist");

      if (at->sbuf)
	{
	  if ((ofs & (~(COM_LEN - 1))) == at->save_pos)
	    {
	      grub_disk_addr_t n;

	      n = COM_LEN - (ofs - at->save_pos);
	      if (n > len)
		n = len;

	      grub_memcpy (dest, at->sbuf + ofs - at->save_pos, n);
	      if (n == len)
		return 0;

	      dest += n;
	      len -= n;
	      ofs += n;
	    }
	}
      else
	{
	  at->sbuf = grub_malloc (COM_LEN);
	  if (at->sbuf == NULL)
	    return grub_errno;
	  at->save_pos = 1;
	}

      vcn = ctx->target_vcn = (ofs >> COM_LOG_LEN) * (COM_SEC / ctx->comp.spc);
      ctx->target_vcn &= ~0xF;
    }
  else
    vcn = ctx->target_vcn = grub_divmod64 (ofs >> BLK_SHR, ctx->comp.spc, 0);

  ctx->next_vcn = u32at (pa, 0x10);
  ctx->curr_lcn = 0;
  while (ctx->next_vcn <= ctx->target_vcn)
    {
      if (grub_ntfs_read_run_list (ctx))
	return grub_errno;
    }

  if (at->flags & AF_GPOS)
    {
      grub_disk_addr_t st0, st1;
      grub_uint32_t m;

      grub_divmod64 (ofs >> BLK_SHR, ctx->comp.spc, &m);

      st0 =
	(ctx->target_vcn - ctx->curr_vcn + ctx->curr_lcn) * ctx->comp.spc + m;
      st1 = st0 + 1;
      if (st1 ==
	  (ctx->next_vcn - ctx->curr_vcn + ctx->curr_lcn) * ctx->comp.spc)
	{
	  if (grub_ntfs_read_run_list (ctx))
	    return grub_errno;
	  st1 = ctx->curr_lcn * ctx->comp.spc;
	}
      v32at (dest, 0) = st0;
      v32at (dest, 4) = st1;
      return 0;
    }

  if (!(ctx->flags & RF_COMP))
    {
      unsigned int pow;

      if (!grub_fshelp_log2blksize (ctx->comp.spc, &pow))
	grub_fshelp_read_file (ctx->comp.disk, (grub_fshelp_node_t) ctx,
			       read_hook, closure, flags, ofs, len, dest,
			       grub_ntfs_read_block, ofs + len, pow);
      return grub_errno;
    }

  return (grub_ntfscomp_func) ? grub_ntfscomp_func (at, dest, ofs, len, ctx,
						    vcn) :
    grub_error (GRUB_ERR_BAD_FS, "ntfscomp module not loaded");
}

static grub_err_t
read_attr (struct grub_ntfs_attr *at, char *dest, grub_disk_addr_t ofs,
	   grub_size_t len, int cached,
	   void (*read_hook) (grub_disk_addr_t sector,
			      unsigned offset,
			      unsigned length,
			      void *closure),
	   void *closure, int flags)
{
  char *save_cur;
  unsigned char attr;
  char *pp;
  grub_err_t ret;

  save_cur = at->attr_cur;
  at->attr_nxt = at->attr_cur;
  attr = (unsigned char) *at->attr_nxt;
  if (at->flags & AF_ALST)
    {
      char *pa;
      grub_disk_addr_t vcn;

      vcn = grub_divmod64 (ofs, at->mft->data->spc << BLK_SHR, 0);
      pa = at->attr_nxt + u16at (at->attr_nxt, 4);
      while (pa < at->attr_end)
	{
	  if ((unsigned char) *pa != attr)
	    break;
	  if (u32at (pa, 8) > vcn)
	    break;
	  at->attr_nxt = pa;
	  pa += u16at (pa, 4);
	}
    }
  pp = find_attr (at, attr);
  if (pp)
    ret = read_data (at, pp, dest, ofs, len, cached, read_hook, closure, flags);
  else
    ret =
      (grub_errno) ? grub_errno : grub_error (GRUB_ERR_BAD_FS,
					      "attribute not found");
  at->attr_cur = save_cur;
  return ret;
}

static void
read_mft_hook (grub_disk_addr_t sector, unsigned offset,
	       unsigned length, void *closure)
{
  grub_uint32_t **s = closure;

  if (*s)
    {
      if ((offset != 0) || (length != GRUB_DISK_SECTOR_SIZE))
	grub_error (GRUB_ERR_BAD_FS, "invalid mft location");
      **s = sector;
      *s = 0;
    }
}

static grub_err_t
read_mft (struct grub_ntfs_data *data, char *buf, grub_uint32_t mftno,
	  grub_uint32_t *sector)
{
  if (read_attr
      (&data->mmft.attr, buf, mftno * ((grub_disk_addr_t) data->mft_size << BLK_SHR),
       data->mft_size << BLK_SHR, 0, read_mft_hook, &sector, 0))
    return grub_error (GRUB_ERR_BAD_FS, "Read MFT 0x%X fails", mftno);
  return fixup (data, buf, data->mft_size, "FILE");
}

static grub_err_t
init_file (struct grub_ntfs_file *mft, grub_uint32_t mftno)
{
  unsigned short flag;

  mft->inode_read = 1;

  mft->buf = grub_malloc (mft->data->mft_size << BLK_SHR);
  if (mft->buf == NULL)
    return grub_errno;

  if (read_mft (mft->data, mft->buf, mftno, &mft->sector))
    return grub_errno;

  flag = u16at (mft->buf, 0x16);
  if ((flag & 1) == 0)
    return grub_error (GRUB_ERR_BAD_FS, "MFT 0x%X is not in use", mftno);

  if ((flag & 2) == 0)
    {
      char *pa;

      pa = locate_attr (&mft->attr, mft, AT_DATA);
      if (pa == NULL)
	return grub_error (GRUB_ERR_BAD_FS, "no $DATA in MFT 0x%X", mftno);

      if (!pa[8])
	mft->size = u32at (pa, 0x10);
      else
	mft->size = u64at (pa, 0x30);

      if ((mft->attr.flags & AF_ALST) == 0)
	mft->attr.attr_end = 0;	/*  Don't jump to attribute list */
    }
  else
    init_attr (&mft->attr, mft);

  return 0;
}

static void
free_file (struct grub_ntfs_file *mft)
{
  free_attr (&mft->attr);
  grub_free (mft->buf);
}

static int
list_file (struct grub_ntfs_file *diro, char *pos,
	   int (*hook) (const char *filename,
			enum grub_fshelp_filetype filetype,
			grub_fshelp_node_t node,
			void *closure),
	   void *closure)
{
  char *np;
  int ns;

  if (hook)
  for (;;)
    {
      char *ustr, namespace;

      if (pos[0xC] & 2)		/* end signature */
	break;

      np = pos + 0x50;
      ns = (unsigned char) *(np++);
      namespace = *(np++);

      /*
       *  Ignore files in DOS namespace, as they will reappear as Win32
       *  names.
       */
      if ((ns) && (namespace != 2))
	{
	  enum grub_fshelp_filetype type;
	  struct grub_ntfs_file *fdiro;

	  if (u16at (pos, 4))
	    {
	      grub_error (GRUB_ERR_BAD_FS, "64-bit MFT number");
	      return 0;
	    }

	  type =
	    (u32at (pos, 0x48) & ATTR_DIRECTORY) ? GRUB_FSHELP_DIR :
	    GRUB_FSHELP_REG;

	  fdiro = grub_zalloc (sizeof (struct grub_ntfs_file));
	  if (!fdiro)
	    return 0;

	  fdiro->data = diro->data;
	  fdiro->ino = u32at (pos, 0);

	  ustr = grub_malloc (ns * 4 + 1);
	  if (ustr == NULL){
		  grub_free(fdiro);
	    return 0;
	  }
	  *grub_utf16_to_utf8 ((grub_uint8_t *) ustr, (grub_uint16_t *) np,
			       ns) = '\0';

          if (namespace)
            type |= GRUB_FSHELP_CASE_INSENSITIVE;

	  if (hook (ustr, type, fdiro, closure))
	    {
	      grub_free (ustr);
	      return 1;
	    }

	  grub_free (ustr);
	}
      pos += u16at (pos, 8);
    }
  return 0;
}

static int
grub_ntfs_iterate_dir (grub_fshelp_node_t dir,
		       int (*hook) (const char *filename,
				    enum grub_fshelp_filetype filetype,
				    grub_fshelp_node_t node,
				    void *closure),
		       void *closure)
{
  unsigned char *bitmap;
  struct grub_ntfs_attr attr, *at;
  char *cur_pos, *indx, *bmp;
  int ret = 0;
  grub_size_t bitmap_len;
  struct grub_ntfs_file *mft;

  mft = (struct grub_ntfs_file *) dir;

  if (!mft->inode_read)
    {
      if (init_file (mft, mft->ino))
	return 0;
    }

  indx = NULL;
  bmp = NULL;

  at = &attr;
  init_attr (at, mft);
  while (1)
    {
      if ((cur_pos = find_attr (at, AT_INDEX_ROOT)) == NULL)
	{
	  grub_error (GRUB_ERR_BAD_FS, "no $INDEX_ROOT");
	  goto done;
	}

      /* Resident, Namelen=4, Offset=0x18, Flags=0x00, Name="$I30" */
      if ((u32at (cur_pos, 8) != 0x180400) ||
	  (u32at (cur_pos, 0x18) != 0x490024) ||
	  (u32at (cur_pos, 0x1C) != 0x300033))
	continue;
      cur_pos += u16at (cur_pos, 0x14);
      if (*cur_pos != 0x30)	/* Not filename index */
	continue;
      break;
    }

  cur_pos += 0x10;		/* Skip index root */
  ret = list_file (mft, cur_pos + u16at (cur_pos, 0), hook, closure);
  if (ret)
    goto done;

  bitmap = NULL;
  bitmap_len = 0;
  free_attr (at);
  init_attr (at, mft);
  while ((cur_pos = find_attr (at, AT_BITMAP)) != NULL)
    {
      int ofs;

      ofs = (unsigned char) cur_pos[0xA];
      /* Namelen=4, Name="$I30" */
      if ((cur_pos[9] == 4) &&
	  (u32at (cur_pos, ofs) == 0x490024) &&
	  (u32at (cur_pos, ofs + 4) == 0x300033))
	{
          int is_resident = (cur_pos[8] == 0);

          bitmap_len = ((is_resident) ? u32at (cur_pos, 0x10) :
                        u32at (cur_pos, 0x28));

          bmp = grub_malloc (bitmap_len);
          if (bmp == NULL)
            goto done;

	  if (is_resident)
	    {
              grub_memcpy (bmp, (char *) (cur_pos + u16at (cur_pos, 0x14)),
                           bitmap_len);
	    }
          else
            {
              if (read_data (at, cur_pos, bmp, 0, bitmap_len, 0, 0, 0, 0))
                {
                  grub_error (GRUB_ERR_BAD_FS,
                              "fails to read non-resident $BITMAP");
                  goto done;
                }
              bitmap_len = u32at (cur_pos, 0x30);
            }

          bitmap = (unsigned char *) bmp;
	  break;
	}
    }

  free_attr (at);
  cur_pos = locate_attr (at, mft, AT_INDEX_ALLOCATION);
  while (cur_pos != NULL)
    {
      /* Non-resident, Namelen=4, Offset=0x40, Flags=0, Name="$I30" */
      if ((u32at (cur_pos, 8) == 0x400401) &&
	  (u32at (cur_pos, 0x40) == 0x490024) &&
	  (u32at (cur_pos, 0x44) == 0x300033))
	break;
      cur_pos = find_attr (at, AT_INDEX_ALLOCATION);
    }

  if ((!cur_pos) && (bitmap))
    {
      grub_error (GRUB_ERR_BAD_FS, "$BITMAP without $INDEX_ALLOCATION");
      goto done;
    }

  if (bitmap)
    {
      grub_disk_addr_t v, i;

      indx = grub_malloc (mft->data->idx_size << BLK_SHR);
      if (indx == NULL)
	goto done;

      v = 1;
      for (i = 0; i < (grub_disk_addr_t)bitmap_len * 8; i++)
	{
	  if (*bitmap & v)
	    {
	      if ((read_attr
		   (at, indx, i * (mft->data->idx_size << BLK_SHR),
		    (mft->data->idx_size << BLK_SHR), 0, 0, 0, 0))
		  || (fixup (mft->data, indx, mft->data->idx_size, "INDX")))
		goto done;
	      ret = list_file (mft, &indx[0x18 + u16at (indx, 0x18)], hook,
			       closure);
	      if (ret)
		goto done;
	    }
	  v <<= 1;
	  if (v >= 0x100)
	    {
	      v = 1;
	      bitmap++;
	    }
	}
    }

done:
  free_attr (at);
  grub_free (indx);
  grub_free (bmp);

  return ret;
}

static struct grub_ntfs_data *
grub_ntfs_mount (grub_disk_t disk)
{
  struct grub_ntfs_bpb bpb;
  struct grub_ntfs_data *data = 0;

  if (!disk)
    goto fail;

  data = (struct grub_ntfs_data *) grub_zalloc (sizeof (*data));
  if (!data)
    goto fail;

  data->disk = disk;

  /* Read the BPB.  */
  if (grub_disk_read (disk, 0, 0, sizeof (bpb), &bpb))
    goto fail;

  if (grub_memcmp ((char *) &bpb.oem_name, "NTFS", 4))
    goto fail;

  data->blocksize = grub_le_to_cpu16 (bpb.bytes_per_sector);
  data->spc = bpb.sectors_per_cluster * (data->blocksize >> BLK_SHR);

  if (bpb.clusters_per_mft > 0)
    data->mft_size = data->spc * bpb.clusters_per_mft;
  else
    data->mft_size = 1 << (-bpb.clusters_per_mft - BLK_SHR);

  if (bpb.clusters_per_index > 0)
    data->idx_size = data->spc * bpb.clusters_per_index;
  else
    data->idx_size = 1 << (-bpb.clusters_per_index - BLK_SHR);

  data->mft_start = grub_le_to_cpu64 (bpb.mft_lcn) * data->spc;

  if ((data->mft_size > MAX_MFT) || (data->idx_size > MAX_IDX))
    goto fail;

  data->mmft.data = data;
  data->cmft.data = data;

  data->mmft.buf = grub_malloc (data->mft_size << BLK_SHR);
  if (!data->mmft.buf)
    goto fail;

  if (grub_disk_read
      (disk, data->mft_start, 0, data->mft_size << BLK_SHR, data->mmft.buf))
    goto fail;
  data->mmft.sector = data->mft_start +
    grub_partition_get_start (disk->partition);

  data->uuid = grub_le_to_cpu64 (bpb.num_serial);

  if (fixup (data, data->mmft.buf, data->mft_size, "FILE"))
    goto fail;

  if (!locate_attr (&data->mmft.attr, &data->mmft, AT_DATA))
    goto fail;

  if (init_file (&data->cmft, FILE_ROOT))
    goto fail;

  return data;

fail:
  grub_error (GRUB_ERR_BAD_FS, "not an ntfs filesystem");

  if (data)
    {
      free_file (&data->mmft);
      free_file (&data->cmft);
      grub_free (data);
    }
  return 0;
}

struct grub_ntfs_dir_closure
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
  struct grub_ntfs_dir_closure *c = closure;
  struct grub_dirhook_info info;
  grub_memset (&info, 0, sizeof (info));
  info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
  grub_free (node);
  return c->hook (filename, &info, c->closure);
}

static grub_err_t
grub_ntfs_dir (grub_device_t device, const char *path,
	       int (*hook) (const char *filename,
			    const struct grub_dirhook_info *info,
			    void *closure),
	       void *closure)
{
  struct grub_ntfs_data *data = 0;
  struct grub_fshelp_node *fdiro = 0;
  struct grub_ntfs_dir_closure c;

  grub_dl_ref (my_mod);

  data = grub_ntfs_mount (device->disk);
  if (!data)
    goto fail;

  grub_fshelp_find_file (path, &data->cmft, &fdiro, grub_ntfs_iterate_dir, 0,
			 0, GRUB_FSHELP_DIR);

  if (grub_errno)
    goto fail;

  c.hook = hook;
  c.closure = closure;
  grub_ntfs_iterate_dir (fdiro, iterate, &c);

fail:
  if ((fdiro) && (fdiro != &data->cmft))
    {
      free_file (fdiro);
      grub_free (fdiro);
    }
  if (data)
    {
      free_file (&data->mmft);
      free_file (&data->cmft);
      grub_free (data);
    }

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_err_t
grub_ntfs_open (grub_file_t file, const char *name)
{
  struct grub_ntfs_data *data = 0;
  struct grub_fshelp_node *mft = 0;

  grub_dl_ref (my_mod);

  data = grub_ntfs_mount (file->device->disk);
  if (!data)
    goto fail;

  grub_fshelp_find_file (name, &data->cmft, &mft, grub_ntfs_iterate_dir, 0,
			 0, GRUB_FSHELP_REG);

  if (grub_errno)
    goto fail;

  if (mft != &data->cmft)
    {
      free_file (&data->cmft);
      grub_memcpy (&data->cmft, mft, sizeof (*mft));
      grub_free (mft);
      if (!data->cmft.inode_read)
	{
	  if (init_file (&data->cmft, data->cmft.ino))
	    goto fail;
	}
    }

  file->size = data->cmft.size;
  file->data = data;
  file->offset = 0;

  return 0;

fail:
  if (data)
    {
      free_file (&data->mmft);
      free_file (&data->cmft);
      grub_free (data);
    }

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_ssize_t
grub_ntfs_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_ntfs_file *mft;

  mft = &((struct grub_ntfs_data *) file->data)->cmft;
  if (file->read_hook)
    mft->attr.save_pos = 1;

  read_attr (&mft->attr, buf, file->offset, len, 1,
	     file->read_hook, file->closure, file->flags);
  return (grub_errno) ? 0 : len;
}

static grub_err_t
grub_ntfs_close (grub_file_t file)
{
  struct grub_ntfs_data *data;

  data = file->data;

  if (data)
    {
      free_file (&data->mmft);
      free_file (&data->cmft);
      grub_free (data);
    }

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_err_t
grub_ntfs_label (grub_device_t device, char **label)
{
  struct grub_ntfs_data *data = 0;
  struct grub_fshelp_node *mft = 0;
  char *pa;

  grub_dl_ref (my_mod);

  *label = 0;

  data = grub_ntfs_mount (device->disk);
  if (!data)
    goto fail;

  grub_fshelp_find_file ("/$Volume", &data->cmft, &mft, grub_ntfs_iterate_dir,
			 0, 0, GRUB_FSHELP_REG);

  if (grub_errno)
    goto fail;

  if (!mft->inode_read)
    {
      mft->buf = grub_malloc (mft->data->mft_size << BLK_SHR);
      if (mft->buf == NULL)
	goto fail;

      if (read_mft (mft->data, mft->buf, mft->ino, &mft->sector))
	goto fail;
    }

  init_attr (&mft->attr, mft);
  pa = find_attr (&mft->attr, AT_VOLUME_NAME);
  if ((pa) && (pa[8] == 0) && (u32at (pa, 0x10)))
    {
      char *buf;
      int len;

      len = u32at (pa, 0x10) / 2;
      buf = grub_malloc (len * 4 + 1);
      pa += u16at (pa, 0x14);
      *grub_utf16_to_utf8 ((grub_uint8_t *) buf, (grub_uint16_t *) pa, len) =
	'\0';
      *label = buf;
    }

fail:
  if ((mft) && (mft != &data->cmft))
    {
      free_file (mft);
      grub_free (mft);
    }
  if (data)
    {
      free_file (&data->mmft);
      free_file (&data->cmft);
      grub_free (data);
    }

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_err_t
grub_ntfs_uuid (grub_device_t device, char **uuid)
{
  struct grub_ntfs_data *data;
  grub_disk_t disk = device->disk;

  grub_dl_ref (my_mod);

  data = grub_ntfs_mount (disk);
  if (data)
    {
      *uuid = grub_xasprintf ("%016llx", (unsigned long long) data->uuid);
    }
  else
    *uuid = NULL;

  grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;
}

struct grub_fs grub_ntfs_fs =
  {
    .name = "ntfs",
    .dir = grub_ntfs_dir,
    .open = grub_ntfs_open,
    .read = grub_ntfs_read,
    .close = grub_ntfs_close,
    .label = grub_ntfs_label,
    .uuid = grub_ntfs_uuid,
#ifdef GRUB_UTIL
    .reserved_first_sector = 1,
#endif
    .next = 0
};
