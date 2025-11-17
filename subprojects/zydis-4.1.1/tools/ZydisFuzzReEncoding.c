/***************************************************************************************************

  Zyan Disassembler Library (Zydis)

  Original Author : Mappa

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
 * This file implements fuzz target for re-encoding. Fuzzer input is passed to decoder first and if
 * it decodes as a valid instruction `ZydisEncoderDecodedInstructionToEncoderRequest` is used to
 * create encoder request which gets passed to the encoder.
 */

#include "ZydisFuzzShared.h"

/* ============================================================================================== */
/* Enums and types                                                                                */
/* ============================================================================================== */

/**
 * Structure for fuzzing decoder inputs.
 */
typedef struct ZydisFuzzControlBlock_
{
    ZydisMachineMode machine_mode;
    ZydisStackWidth stack_width;
} ZydisFuzzControlBlock;

/* ============================================================================================== */
/* Fuzz target                                                                                    */
/* ============================================================================================== */

ZYAN_NO_SANITIZE("enum")
int ZydisFuzzTarget(ZydisStreamRead read_fn, void *stream_ctx)
{
    ZydisFuzzControlBlock control_block;
    if (read_fn(
        stream_ctx, (ZyanU8 *)&control_block, sizeof(control_block)) != sizeof(control_block))
    {
        ZYDIS_MAYBE_FPUTS("Not enough bytes to fuzz\n", ZYAN_STDERR);
        return EXIT_SUCCESS;
    }

    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, control_block.machine_mode,
        control_block.stack_width)))
    {
        ZYDIS_MAYBE_FPUTS("Failed to initialize decoder\n", ZYAN_STDERR);
        return EXIT_FAILURE;
    }

    ZyanU8 buffer[32];
    ZyanUSize input_len = read_fn(stream_ctx, buffer, sizeof(buffer));

    ZydisDecodedInstruction insn1;
    ZydisDecodedOperand operands1[ZYDIS_MAX_OPERAND_COUNT];
    ZyanStatus status = ZydisDecoderDecodeFull(&decoder, buffer, input_len, &insn1, operands1);
    if (!ZYAN_SUCCESS(status))
    {
        return EXIT_FAILURE;
    }

    ZydisReEncodeInstruction(&decoder, &insn1, operands1, insn1.operand_count_visible, buffer);

    return EXIT_SUCCESS;
}

/* ============================================================================================== */
