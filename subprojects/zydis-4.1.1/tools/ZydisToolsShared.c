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

/**
 * @file
 *
 * This file contains common functions used by the Zydis tool projects.
 */

#include "ZydisToolsShared.h"

#include <inttypes.h>

/* ============================================================================================== */
/* Colors                                                                                         */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* Global variables                                                                               */
/* ---------------------------------------------------------------------------------------------- */

ZyanBool g_vt100_stdout;
ZyanBool g_vt100_stderr;

/* ---------------------------------------------------------------------------------------------- */
/* Functions                                                                                      */
/* ---------------------------------------------------------------------------------------------- */

void InitVT100(void)
{
    // See https://no-color.org/ for more information about this informal standard.
    char* env_no_color = ZYAN_GETENV("NO_COLOR");
    char* env_force_color = ZYAN_GETENV("FORCE_COLOR");
    ZyanBool no_color = ((env_no_color != ZYAN_NULL) && (env_no_color[0] != '\0'));
    ZyanBool force_color = ((env_force_color != ZYAN_NULL) && (env_force_color[0] != '\0'));

    // Enable VT100 escape sequences on Windows, if the output is not redirected
    g_vt100_stdout = force_color || (!no_color &&
        (ZyanTerminalIsTTY(ZYAN_STDSTREAM_OUT) == ZYAN_STATUS_TRUE) &&
        ZYAN_SUCCESS(ZyanTerminalEnableVT100(ZYAN_STDSTREAM_OUT)));
    g_vt100_stderr = force_color || (!no_color &&
        (ZyanTerminalIsTTY(ZYAN_STDSTREAM_ERR) == ZYAN_STATUS_TRUE) &&
        ZYAN_SUCCESS(ZyanTerminalEnableVT100(ZYAN_STDSTREAM_ERR)));
}

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
/* Helper functions                                                                               */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* General                                                                                        */
/* ---------------------------------------------------------------------------------------------- */

const char* FormatZyanStatus(ZyanStatus status)
{
    static const char* strings_zycore[] =
    {
        /* 00 */ "SUCCESS",
        /* 01 */ "FAILED",
        /* 02 */ "TRUE",
        /* 03 */ "FALSE",
        /* 04 */ "INVALID_ARGUMENT",
        /* 05 */ "INVALID_OPERATION",
        /* 06 */ "NOT_FOUND",
        /* 07 */ "OUT_OF_RANGE",
        /* 08 */ "INSUFFICIENT_BUFFER_SIZE",
        /* 09 */ "NOT_ENOUGH_MEMORY",
        /* 0A */ "NOT_ENOUGH_MEMORY",
        /* 0B */ "BAD_SYSTEMCALL"
    };
    static const char* strings_zydis[] =
    {
        /* 00 */ "NO_MORE_DATA",
        /* 01 */ "DECODING_ERROR",
        /* 02 */ "INSTRUCTION_TOO_LONG",
        /* 03 */ "BAD_REGISTER",
        /* 04 */ "ILLEGAL_LOCK",
        /* 05 */ "ILLEGAL_LEGACY_PFX",
        /* 06 */ "ILLEGAL_REX",
        /* 07 */ "INVALID_MAP",
        /* 08 */ "MALFORMED_EVEX",
        /* 09 */ "MALFORMED_MVEX",
        /* 0A */ "INVALID_MASK",
        /* 0B */ "SKIP_TOKEN",
        /* 0C */ "IMPOSSIBLE_INSTRUCTION"
    };

    if (ZYAN_STATUS_MODULE(status) == ZYAN_MODULE_ZYCORE)
    {
        status = ZYAN_STATUS_CODE(status);
        ZYAN_ASSERT(status < ZYAN_ARRAY_LENGTH(strings_zycore));
        return strings_zycore[status];
    }

    if (ZYAN_STATUS_MODULE(status) == ZYAN_MODULE_ZYDIS)
    {
        status = ZYAN_STATUS_CODE(status);
        ZYAN_ASSERT(status < ZYAN_ARRAY_LENGTH(strings_zydis));
        return strings_zydis[status];
    }

    ZYAN_UNREACHABLE;
}

/* ---------------------------------------------------------------------------------------------- */
/* Text output                                                                                    */
/* ---------------------------------------------------------------------------------------------- */

void PrintStatusError(ZyanStatus status, const char* message)
{
    ZYAN_ASSERT(ZYAN_FAILED(status));

    if (ZYAN_STATUS_MODULE(status) >= ZYAN_MODULE_USER)
    {
        ZYAN_FPRINTF(ZYAN_STDERR,
            "%s%s: User defined status code [0x%" PRIx32 "]%s\n",
            CVT100_ERR(COLOR_ERROR), message, status,
            CVT100_ERR(ZYAN_VT100SGR_RESET));
    }
    else
    {
        ZYAN_FPRINTF(ZYAN_STDERR, "%s%s: %s [0x%" PRIx32 "]%s\n",
            CVT100_ERR(COLOR_ERROR), message, FormatZyanStatus(status), status,
            CVT100_ERR(ZYAN_VT100SGR_RESET));
    }
}

/**
 * Prints a tokenized instruction.
 *
 * @param   token   A pointer to the first token.
 */
void PrintTokenizedInstruction(const ZydisFormatterToken* token)
{
    ZyanStatus status = ZYAN_STATUS_SUCCESS;
    while (ZYAN_SUCCESS(status))
    {
        ZydisTokenType type;
        ZyanConstCharPointer value;
        if (!ZYAN_SUCCESS(status = ZydisFormatterTokenGetValue(token, &type, &value)))
        {
            PrintStatusError(status, "Failed to get token value");
            exit(status);
        }

        const char* color;
        switch (token->type)
        {
        case ZYDIS_TOKEN_DELIMITER:
            ZYAN_FALLTHROUGH;
        case ZYDIS_TOKEN_PARENTHESIS_OPEN:
            ZYAN_FALLTHROUGH;
        case ZYDIS_TOKEN_PARENTHESIS_CLOSE:
            color = CVT100_OUT(COLOR_TOKEN_DEFAULT);
            break;
        case ZYDIS_TOKEN_PREFIX:
            color = CVT100_OUT(COLOR_TOKEN_PREFIX);
            break;
        case ZYDIS_TOKEN_MNEMONIC:
            color = CVT100_OUT(COLOR_TOKEN_MNEMONIC);
            break;
        case ZYDIS_TOKEN_REGISTER:
            color = CVT100_OUT(COLOR_TOKEN_REG);
            break;
        case ZYDIS_TOKEN_ADDRESS_ABS:
        case ZYDIS_TOKEN_ADDRESS_REL:
            color = CVT100_OUT(COLOR_TOKEN_ADDR);
            break;
        case ZYDIS_TOKEN_DISPLACEMENT:
            color = CVT100_OUT(COLOR_TOKEN_DISP);
            break;
        case ZYDIS_TOKEN_IMMEDIATE:
            color = CVT100_OUT(COLOR_TOKEN_IMM);
            break;
        case ZYDIS_TOKEN_TYPECAST:
            color = CVT100_OUT(ZYAN_VT100SGR_FG_WHITE);
            break;
        case ZYDIS_TOKEN_DECORATOR:
            color = CVT100_OUT(ZYAN_VT100SGR_FG_WHITE);
            break;
        default:
            color = CVT100_OUT(COLOR_DEFAULT);
            break;
        }
        ZYAN_PRINTF("%s%s", color, value);

        status = ZydisFormatterTokenNext(&token);
    }
    ZYAN_ASSERT(status == ZYAN_STATUS_OUT_OF_RANGE);

    ZYAN_PRINTF("%s\n", CVT100_OUT(COLOR_DEFAULT));
}

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
