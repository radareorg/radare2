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

static inline size_t gdbr_reg_byte_end(const gdb_reg_t *reg) {
	return (reg->offset + reg->size + 7) / 8;
}

/* Grow g->data so a response of len bytes and its terminator fit. */
static inline bool gdbr_ensure_data_capacity(libgdbr_t *g, size_t len) {
	if (!g) {
		return false;
	}
	if (len < (size_t)g->data_max) {
		return true;
	}
	size_t newsize = g->data_max > 0? (size_t)g->data_max: 4096;
	while (newsize <= len) {
		newsize *= 2;
	}
	char *data = realloc (g->data, newsize);
	if (!data) {
		return false;
	}
	g->data = data;
	g->data_max = newsize;
	return true;
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
