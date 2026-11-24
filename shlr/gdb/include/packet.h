/*! \file */
#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "libgdbr.h"
#include <stdio.h>
#if R2__WINDOWS__
#include <windows.h>
#if !defined(_MSC_VER)
#include <winsock.h>
#endif
#endif
/*!
 * \brief sends a packet sends a packet to the established connection
 * \param g the "instance" of the current libgdbr session
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int send_packet(libgdbr_t *g);

/*!
 * \brief Function reads data from the established connection
 * \param g the "instance" of the current libgdbr session
 * \param vcont whether it's called to receive reply to a vcont packet
 * \returns 0 for a complete packet, GDBR_READ_TIMEOUT for an idle poll, or -1 on failure
 */
#define GDBR_READ_TIMEOUT (-2)
#define GDBR_READ_NOTIFICATION (-3)
#define GDBR_READ_INTERRUPTED (-4)
int read_packet(libgdbr_t *g, bool vcont);

int pack(libgdbr_t *g, const char *msg);

#endif
