#if NOT_USER_RIGHT_NOW
/* ntfscomp.c - compression support for the NTFS filesystem */
/*
 *  Copyright (C) 2007 Free Software Foundation, Inc.
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

static grub_err_t
decomp_nextvcn (struct grub_ntfs_comp *cc)
{
  if (cc->comp_head >= cc->comp_tail)
    return grub_error (GRUB_ERR_BAD_FS, "compression block overflown");
  if (grub_disk_read
      (cc->disk,
       (cc->comp_table[cc->comp_head][1] -
	(cc->comp_table[cc->comp_head][0] - cc->cbuf_vcn)) * cc->spc, 0,
       cc->spc << BLK_SHR, cc->cbuf))
    return grub_errno;
  cc->cbuf_vcn++;
  if ((cc->cbuf_vcn >= cc->comp_table[cc->comp_head][0]))
    cc->comp_head++;
  cc->cbuf_ofs = 0;
  return 0;
}

static grub_err_t
decomp_getch (struct grub_ntfs_comp *cc, unsigned char *res)
{
  if (cc->cbuf_ofs >= (cc->spc << BLK_SHR))
    {
      if (decomp_nextvcn (cc))
	return grub_errno;
    }
  *res = (unsigned char) cc->cbuf[cc->cbuf_ofs++];
  return 0;
}

static grub_err_t
decomp_get16 (struct grub_ntfs_comp *cc, grub_uint16_t * res)
{
  unsigned char c1 = 0, c2 = 0;

  if ((decomp_getch (cc, &c1)) || (decomp_getch (cc, &c2)))
    return grub_errno;
  *res = ((grub_uint16_t) c2) * 256 + ((grub_uint16_t) c1);
  return 0;
}

/* Decompress a block (4096 bytes) */
static grub_err_t
decomp_block (struct grub_ntfs_comp *cc, char *dest)
{
  grub_uint16_t flg, cnt;

  if (decomp_get16 (cc, &flg))
    return grub_errno;
  cnt = (flg & 0xFFF) + 1;

  if (dest)
    {
      if (flg & 0x8000)
	{
	  unsigned char tag;
	  grub_uint32_t bits, copied;

	  bits = copied = tag = 0;
	  while (cnt > 0)
	    {
	      if (copied > COM_LEN)
		return grub_error (GRUB_ERR_BAD_FS,
				   "compression block too large");

	      if (!bits)
		{
		  if (decomp_getch (cc, &tag))
		    return grub_errno;

		  bits = 8;
		  cnt--;
		  if (cnt <= 0)
		    break;
		}
	      if (tag & 1)
		{
		  grub_uint32_t i, len, delta, code, lmask, dshift;
		  grub_uint16_t word;

		  if (decomp_get16 (cc, &word))
		    return grub_errno;

		  code = word;
		  cnt -= 2;

		  if (!copied)
		    {
		      grub_error (GRUB_ERR_BAD_FS, "nontext window empty");
		      return 0;
		    }

		  for (i = copied - 1, lmask = 0xFFF, dshift = 12; i >= 0x10;
		       i >>= 1)
		    {
		      lmask >>= 1;
		      dshift--;
		    }

		  delta = code >> dshift;
		  len = (code & lmask) + 3;

		  for (i = 0; i < len; i++)
		    {
		      dest[copied] = dest[copied - delta - 1];
		      copied++;
		    }
		}
	      else
		{
		  unsigned char ch = 0;

		  if (decomp_getch (cc, &ch))
		    return grub_errno;
		  dest[copied++] = ch;
		  cnt--;
		}
	      tag >>= 1;
	      bits--;
	    }
	  return 0;
	}
      else
	{
	  if (cnt != COM_LEN)
	    return grub_error (GRUB_ERR_BAD_FS,
			       "invalid compression block size");
	}
    }

  while (cnt > 0)
    {
      int n;

      n = (cc->spc << BLK_SHR) - cc->cbuf_ofs;
      if (n > cnt)
	n = cnt;
      if ((dest) && (n))
	{
	  grub_memcpy (dest, &cc->cbuf[cc->cbuf_ofs], n);
	  dest += n;
	}
      cnt -= n;
      cc->cbuf_ofs += n;
      if ((cnt) && (decomp_nextvcn (cc)))
	return grub_errno;
    }
  return 0;
}

static grub_err_t
read_block (struct grub_ntfs_rlst *ctx, char *buf, int num)
{
  int cpb = COM_SEC / ctx->comp.spc;

  while (num)
    {
      int nn;

      if ((ctx->target_vcn & 0xF) == 0)
	{

	  if (ctx->comp.comp_head != ctx->comp.comp_tail)
	    return grub_error (GRUB_ERR_BAD_FS, "invalid compression block");
	  ctx->comp.comp_head = ctx->comp.comp_tail = 0;
	  ctx->comp.cbuf_vcn = ctx->target_vcn;
	  ctx->comp.cbuf_ofs = (ctx->comp.spc << BLK_SHR);
	  if (ctx->target_vcn >= ctx->next_vcn)
	    {
	      if (grub_ntfs_read_run_list (ctx))
		return grub_errno;
	    }
	  while (ctx->target_vcn + 16 > ctx->next_vcn)
	    {
	      if (ctx->flags & RF_BLNK)
		break;
	      ctx->comp.comp_table[ctx->comp.comp_tail][0] = ctx->next_vcn;
	      ctx->comp.comp_table[ctx->comp.comp_tail][1] =
		ctx->curr_lcn + ctx->next_vcn - ctx->curr_vcn;
	      ctx->comp.comp_tail++;
	      if (grub_ntfs_read_run_list (ctx))
		return grub_errno;
	    }
	}

      nn = (16 - (unsigned) (ctx->target_vcn & 0xF)) / cpb;
      if (nn > num)
	nn = num;
      num -= nn;

      if (ctx->flags & RF_BLNK)
	{
	  ctx->target_vcn += nn * cpb;
	  if (ctx->comp.comp_tail == 0)
	    {
	      if (buf)
		{
		  grub_memset (buf, 0, nn * COM_LEN);
		  buf += nn * COM_LEN;
		}
	    }
	  else
	    {
	      while (nn)
		{
		  if (decomp_block (&ctx->comp, buf))
		    return grub_errno;
		  if (buf)
		    buf += COM_LEN;
		  nn--;
		}
	    }
	}
      else
	{
	  nn *= cpb;
	  while ((ctx->comp.comp_head < ctx->comp.comp_tail) && (nn))
	    {
	      int tt;

	      tt =
		ctx->comp.comp_table[ctx->comp.comp_head][0] -
		ctx->target_vcn;
	      if (tt > nn)
		tt = nn;
	      ctx->target_vcn += tt;
	      if (buf)
		{
		  if (grub_disk_read
		      (ctx->comp.disk,
		       (ctx->comp.comp_table[ctx->comp.comp_head][1] -
			(ctx->comp.comp_table[ctx->comp.comp_head][0] -
			 ctx->target_vcn)) * ctx->comp.spc, 0,
		       tt * (ctx->comp.spc << BLK_SHR), buf))
		    return grub_errno;
		  buf += tt * (ctx->comp.spc << BLK_SHR);
		}
	      nn -= tt;
	      if (ctx->target_vcn >=
		  ctx->comp.comp_table[ctx->comp.comp_head][0])
		ctx->comp.comp_head++;
	    }
	  if (nn)
	    {
	      if (buf)
		{
		  if (grub_disk_read
		      (ctx->comp.disk,
		       (ctx->target_vcn - ctx->curr_vcn +
			ctx->curr_lcn) * ctx->comp.spc, 0,
		       nn * (ctx->comp.spc << BLK_SHR), buf))
		    return grub_errno;
		  buf += nn * (ctx->comp.spc << BLK_SHR);
		}
	      ctx->target_vcn += nn;
	    }
	}
    }
  return 0;
}

static grub_err_t
ntfscomp (struct grub_ntfs_attr *at, char *dest, grub_uint32_t ofs,
	  grub_uint32_t len, struct grub_ntfs_rlst *ctx, grub_uint32_t vcn)
{
  grub_err_t ret;

  ctx->comp.comp_head = ctx->comp.comp_tail = 0;
  ctx->comp.cbuf = grub_malloc ((ctx->comp.spc) << BLK_SHR);
  if (!ctx->comp.cbuf)
    return 0;

  ret = 0;

  //ctx->comp.disk->read_hook = read_hook;

  if ((vcn > ctx->target_vcn) &&
      (read_block
       (ctx, NULL, ((vcn - ctx->target_vcn) * ctx->comp.spc) / COM_SEC)))
    {
      ret = grub_errno;
      goto quit;
    }

  if (ofs % COM_LEN)
    {
      grub_uint32_t t, n, o;

      t = ctx->target_vcn * (ctx->comp.spc << BLK_SHR);
      if (read_block (ctx, at->sbuf, 1))
	{
	  ret = grub_errno;
	  goto quit;
	}

      at->save_pos = t;

      o = ofs % COM_LEN;
      n = COM_LEN - o;
      if (n > len)
	n = len;
      grub_memcpy (dest, &at->sbuf[o], n);
      if (n == len)
	goto quit;
      dest += n;
      len -= n;
    }

  if (read_block (ctx, dest, len / COM_LEN))
    {
      ret = grub_errno;
      goto quit;
    }

  dest += (len / COM_LEN) * COM_LEN;
  len = len % COM_LEN;
  if (len)
    {
      grub_uint32_t t;

      t = ctx->target_vcn * (ctx->comp.spc << BLK_SHR);
      if (read_block (ctx, at->sbuf, 1))
	{
	  ret = grub_errno;
	  goto quit;
	}

      at->save_pos = t;

      grub_memcpy (dest, at->sbuf, len);
    }

quit:
  //ctx->comp.disk->read_hook = 0;
  if (ctx->comp.cbuf)
    grub_free (ctx->comp.cbuf);
  return ret;
}
#endif
