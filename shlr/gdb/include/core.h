/*! \file */
#ifndef CORE_H
#define CORE_H

#include "r_types.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "libgdbr.h"
#include "utils.h"
#include "arch.h"

#define CMD_READREGS	"g"
#define CMD_WRITEREGS	"G"
#define CMD_WRITEMEM	"M"
#define CMD_READMEM		"m"

#define CMD_BP				"Z0"
#define CMD_RBP				"z0"
#define CMD_QRCMD			"qRcmd,"
#define CMD_C					"vCont"
#define CMD_C_CONT		"c"
#define CMD_C_STEP		"s"


/*!
 * \brief Function sends a command to the gdbserver 
 * \param instance the "instance" of the current libgdbr session
 * \param command the command that will be sent
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int send_command(libgdbr_t* instance, char* command);

/*!
 * \brief Function sends a vCont command to the gdbserver
 * \param instance thre "instance" of the current libgdbr session
 * \param command the command that will be sent (i.e. 's,S,c,C...')
 * \returns -1 if something went wrong
 */
int send_vcont(libgdbr_t* instance, char* command, int thread_id);

/*!
 * \brief Functions sends a single ack ('+')
 * \param instance thre "instance" of the current libgdbr session
 * \returns -1 if something went wrong
 */
int send_ack(libgdbr_t* instance);

#endif
