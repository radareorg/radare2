#ifndef GDBR_COMMON_H_
#define GDBR_COMMON_H_

#include "libgdbr.h"

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
