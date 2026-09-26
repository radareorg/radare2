#ifndef GDBR_COMMON_H_
#define GDBR_COMMON_H_

#include "libgdbr.h"

/* Register offsets and sizes are stated in bits; the buffer is bytes. */
static inline size_t gdbr_reg_byte_offset(const gdb_reg_t *reg) {
	return reg->offset / 8;
}

static inline size_t gdbr_reg_byte_size(const gdb_reg_t *reg) {
	return (reg->size + 7) / 8;
}

/* Bytes a register block may span. The largest register files, SME's ZA included, are
 * far below it: a profile or target.xml stating more cannot be laid out in memory. */
#define GDBR_REGS_MAX ((size_t)1 << 20)

/* The byte after the register's last one; false when that lies beyond GDBR_REGS_MAX */
static inline bool gdbr_reg_byte_end(const gdb_reg_t *reg, size_t *end) {
	const ut64 max = (ut64)GDBR_REGS_MAX * 8;
	if (reg->offset > max || reg->size > max - reg->offset) {
		return false;
	}
	*end = (size_t)((reg->offset + reg->size + 7) / 8);
	return true;
}

/* Half the largest length a ssize_t (data_max) states, so growing to it never wraps */
#define GDBR_GROW_MAX ((size_t)1 << (sizeof (ssize_t) * 8 - 2))

/* Size to grow a buffer to so it holds len bytes and a terminator: the next power of two.
 * A length that would make that size wrap is refused; it can only come from the remote. */
static inline bool gdbr_grow_size(size_t len, size_t *size) {
	if (len >= GDBR_GROW_MAX) {
		return false;
	}
	size_t n = 64;
	while (n <= len) {
		n <<= 1;
	}
	*size = n;
	return true;
}

/* Make g->data hold len bytes and a terminator */
static inline bool gdbr_data_reserve(libgdbr_t *g, size_t len) {
	if (len < (size_t)g->data_max) {
		return true;
	}
	size_t size;
	if (!gdbr_grow_size (len, &size)) {
		return false;
	}
	char *data = realloc (g->data, size);
	if (!data) {
		return false;
	}
	g->data = data;
	g->data_max = (ssize_t)size;
	return true;
}

/* Forget the register values: the thread ran, another one was selected, or the profile changed */
static inline void gdbr_regs_invalidate(libgdbr_t *g) {
	g->regs.valid = false;
	g->regs.refused = false;
	g->regs.len = 0;
	g->regs.count = 0;
}

int handle_qSupported(libgdbr_t *g);

/*!
 * \brief Function sends a message to the remote gdb instance
 * \param g the "instance" of the current libgdbr session
 * \param msg the message that will be sent
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int send_msg(libgdbr_t* g, const char* msg);

/*!
 * \brief Functions sends a single ack ('+')
 * \param g the "instance" of the current libgdbr session
 * \returns -1 if something went wrong
 */
int send_ack(libgdbr_t* g);


#endif  // GDBR_COMMON_H_
