/*! \file */
#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "libgdbr.h"
#include <stdio.h>
#if __WINDOWS__
#include <windows.h>
#if !__CYGWIN__ && !defined(_MSC_VER)
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
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int read_packet(libgdbr_t *g);

int pack(libgdbr_t *g, const char *msg);

#endif
