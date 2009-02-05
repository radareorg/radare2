/* -----------------------------------------------------------------------------
 * input.c
 *
 * Copyright (c) 2004, 2005, 2006, Vivek Mohan <vivek@sig9.com>
 * All rights reserved. See LICENSE
 * -----------------------------------------------------------------------------
 */
#include "extern.h"
#include "types.h"
#include "input.h"

/* -----------------------------------------------------------------------------
 * inp_buff_hook() - Hook for buffered inputs.
 * -----------------------------------------------------------------------------
 */
static int 
inp_buff_hook(struct ud* u)
{
  if (u->inp_buff < u->inp_buff_end)
	return *u->inp_buff++;
  else	return -1;
}

#ifndef __UD_STANDALONE__
/* -----------------------------------------------------------------------------
 * inp_file_hook() - Hook for FILE inputs.
 * -----------------------------------------------------------------------------
 */
static int 
inp_file_hook(struct ud* u)
{
  return fgetc(u->inp_file);
}
#endif /* __UD_STANDALONE__*/

/* =============================================================================
 * ud_inp_set_hook() - Sets input hook.
 * =============================================================================
 */
extern void 
ud_set_input_hook(register struct ud* u, int (*hook)(struct ud*))
{
  u->inp_hook = hook;
  inp_init(u);
}

/* =============================================================================
 * ud_inp_set_buffer() - Set buffer as input.
 * =============================================================================
 */
extern void 
ud_set_input_buffer(register struct ud* u, uint8_t* buf, size_t len)
{
  u->inp_hook = inp_buff_hook;
  u->inp_buff = buf;
  u->inp_buff_end = buf + len;
  inp_init(u);
}

#ifndef __UD_STANDALONE__
/* =============================================================================
 * ud_input_set_file() - Set buffer as input.
 * =============================================================================
 */
extern void 
ud_set_input_file(register struct ud* u, FILE* f)
{
  u->inp_hook = inp_file_hook;
  u->inp_file = f;
  inp_init(u);
}
#endif /* __UD_STANDALONE__ */

/* =============================================================================
 * ud_input_skip() - Skip n input bytes.
 * =============================================================================
 */
extern void 
ud_input_skip(struct ud* u, size_t n)
{
  while (n--) {
	u->inp_hook(u);
  }
}

/* =============================================================================
 * ud_input_end() - Test for end of input.
 * =============================================================================
 */
extern int 
ud_input_end(struct ud* u)
{
  return (u->inp_curr == u->inp_fill) && u->inp_end;
}

/* -----------------------------------------------------------------------------
 * inp_next() - Loads and returns the next byte from input.
 *
 * inp_curr and inp_fill are pointers to the cache. The program is written based
 * on the property that they are 8-bits in size, and will eventually wrap around
 * forming a circular buffer. So, the size of the cache is 256 in size, kind of
 * unnecessary yet optimized.
 *
 * A buffer inp_sess stores the bytes disassembled for a single session.
 * -----------------------------------------------------------------------------
 */
extern uint8_t inp_next(struct ud* u) 
{
  int c = -1;
  /* if current pointer is not upto the fill point in the 
   * input cache.
   */
  if ( u->inp_curr != u->inp_fill ) {
	c = u->inp_cache[ ++u->inp_curr ];
  /* if !end-of-input, call the input hook and get a byte */
  } else if ( u->inp_end || ( c = u->inp_hook( u ) ) == -1 ) {
	/* end-of-input, mark it as an error, since the decoder,
	 * expected a byte more.
	 */
	u->error = 1;
	/* flag end of input */
	u->inp_end = 1;
	return 0;
  } else {
	/* increment pointers, we have a new byte.  */
	u->inp_curr = ++u->inp_fill;
	/* add the byte to the cache */
	u->inp_cache[ u->inp_fill ] = c;
  }
  /* record bytes input per decode-session. */
  u->inp_sess[ u->inp_ctr++ ] = c;
  /* return byte */
  return ( uint8_t ) c;
}

/* -----------------------------------------------------------------------------
 * inp_back() - Move back a single byte in the stream.
 * -----------------------------------------------------------------------------
 */
extern void
inp_back(struct ud* u) 
{
  if ( u->inp_ctr > 0 ) {
	--u->inp_curr;
	--u->inp_ctr;
  }
}

/* -----------------------------------------------------------------------------
 * inp_peek() - Peek into the next byte in source. 
 * -----------------------------------------------------------------------------
 */
extern uint8_t
inp_peek(struct ud* u) 
{
  uint8_t r = inp_next(u);
  if ( !u->error ) inp_back(u); /* Don't backup if there was an error */
  return r;
}

/* -----------------------------------------------------------------------------
 * inp_move() - Move ahead n input bytes.
 * -----------------------------------------------------------------------------
 */
extern void
inp_move(struct ud* u, size_t n) 
{
  while (n--)
	inp_next(u);
}

/*------------------------------------------------------------------------------
 *  inp_uintN() - return uintN from source.
 *------------------------------------------------------------------------------
 */
extern uint8_t 
inp_uint8(struct ud* u)
{
  return inp_next(u);
}

extern uint16_t 
inp_uint16(struct ud* u)
{
  uint16_t r, ret;

  ret = inp_next(u);
  r = inp_next(u);
  return ret | (r << 8);
}

extern uint32_t 
inp_uint32(struct ud* u)
{
  uint32_t r, ret;

  ret = inp_next(u);
  r = inp_next(u);
  ret = ret | (r << 8);
  r = inp_next(u);
  ret = ret | (r << 16);
  r = inp_next(u);
  return ret | (r << 24);
}

extern uint64_t 
inp_uint64(struct ud* u)
{
  uint64_t r, ret;

  ret = inp_next(u);
  r = inp_next(u);
  ret = ret | (r << 8);
  r = inp_next(u);
  ret = ret | (r << 16);
  r = inp_next(u);
  ret = ret | (r << 24);
  r = inp_next(u);
  ret = ret | (r << 32);
  r = inp_next(u);
  ret = ret | (r << 40);
  r = inp_next(u);
  ret = ret | (r << 48);
  r = inp_next(u);
  return ret | (r << 56);
}
