/***************************************************************************************************

  Zyan Disassembler Library (Zydis)

  Original Author : Florian Bernd

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.

***************************************************************************************************/

#ifndef ZYDIS_TOOLSSHARED_H
#define ZYDIS_TOOLSSHARED_H

#include <Zycore/API/Terminal.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>

/* ============================================================================================== */
/* Colors                                                                                         */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* Configuration                                                                                  */
/* ---------------------------------------------------------------------------------------------- */

#define COLOR_DEFAULT           ZYAN_VT100SGR_FG_DEFAULT
#define COLOR_ERROR             ZYAN_VT100SGR_FG_BRIGHT_RED

#define COLOR_TOKEN_ADDR        ZYAN_VT100SGR_FG_BRIGHT_GREEN
#define COLOR_TOKEN_DECORATOR   ZYAN_VT100SGR_FG_WHITE
#define COLOR_TOKEN_DEFAULT     ZYAN_VT100SGR_FG_WHITE
#define COLOR_TOKEN_DISP        ZYAN_VT100SGR_FG_BRIGHT_GREEN
#define COLOR_TOKEN_IMM         ZYAN_VT100SGR_FG_BRIGHT_RED
#define COLOR_TOKEN_MNEMONIC    ZYAN_VT100SGR_FG_BRIGHT_MAGENTA
#define COLOR_TOKEN_PREFIX      ZYAN_VT100SGR_FG_BRIGHT_MAGENTA
#define COLOR_TOKEN_REG         ZYAN_VT100SGR_FG_BRIGHT_BLUE
#define COLOR_TOKEN_TYPECAST    ZYAN_VT100SGR_FG_WHITE

/* ---------------------------------------------------------------------------------------------- */
/* Global variables                                                                               */
/* ---------------------------------------------------------------------------------------------- */

extern ZyanBool g_vt100_stdout;
extern ZyanBool g_vt100_stderr;

/* ---------------------------------------------------------------------------------------------- */
/* Macros                                                                                         */
/* ---------------------------------------------------------------------------------------------- */

/**
 * Conditionally expands to the passed VT100 sequence, if `g_colors_stdout` is
 * `ZYAN_TRUE`, or an empty string, if not.
 *
 * @param   The VT100 SGT sequence.
 */
#define CVT100_OUT(sequence) (g_vt100_stdout ? (sequence) : "")

/**
 * Conditionally expands to the passed VT100 sequence, if `g_colors_stderr` is
 * `ZYAN_TRUE`, or an empty string, if not.
 *
 * @param   The VT100 SGT sequence.
 */
#define CVT100_ERR(sequence) (g_vt100_stderr ? (sequence) : "")

/* ---------------------------------------------------------------------------------------------- */
/* Functions                                                                                      */
/* ---------------------------------------------------------------------------------------------- */

/**
 * Initializes the VT100 capabilities of the terminal and determines if the program should use
 * colored output.
 */
void InitVT100(void);

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
/* Helper functions                                                                               */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* General                                                                                        */
/* ---------------------------------------------------------------------------------------------- */

/**
 * Formats the given zyan status code to a human readable string.
 *
 * @param   status  The zyan status code.
 *
 * @return  The status code string.
 */
const char* FormatZyanStatus(ZyanStatus status);

/* ---------------------------------------------------------------------------------------------- */
/* Text output                                                                                    */
/* ---------------------------------------------------------------------------------------------- */

/**
 * Prints the given error message and status code.
 *
 * @param   status  The status code.
 * @param   message The error message.
*/
void PrintStatusError(ZyanStatus status, const char* message);

/**
 * Prints a tokenized instruction.
 *
 * @param   token   A pointer to the first token.
 */
void PrintTokenizedInstruction(const ZydisFormatterToken* token);

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */

#endif /* ZYDIS_TOOLSSHARED_H */
