/***************************************************************************************************

  Zyan Disassembler Library (Zydis)

  Original Author : Joel Hoener

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
 * This file implements fuzz target for decoder, formatter and various utility functions.
 */

#include "ZydisFuzzShared.h"

/* ============================================================================================== */
/* Enums and types                                                                                */
/* ============================================================================================== */

/**
 * Main fuzzer control block data structure.
 */
typedef struct ZydisFuzzControlBlock_
{
    ZydisMachineMode machine_mode;
    ZydisStackWidth stack_width;
    ZyanBool decoder_mode[ZYDIS_DECODER_MODE_MAX_VALUE + 1];
    ZydisFormatterStyle formatter_style;
    ZyanU64 u64; // u64 used for all kind of non-overlapping purposes
    ZyanUPointer formatter_properties[ZYDIS_FORMATTER_PROP_MAX_VALUE + 1];
    char string[16];
    ZyanU16 formatter_max_len;
} ZydisFuzzControlBlock;

/* ============================================================================================== */
/* Fuzz target                                                                                    */
/* ============================================================================================== */

// We disable enum sanitization here because we actually want Zydis to be tested with
// possibly invalid enum values in mind, thus need to be able to create them here.
ZYAN_NO_SANITIZE("enum")
int ZydisFuzzTarget(ZydisStreamRead read_fn, void* stream_ctx)
{
    ZydisFuzzControlBlock control_block;
    if (read_fn(
        stream_ctx, (ZyanU8*)&control_block, sizeof(control_block)) != sizeof(control_block))
    {
        ZYDIS_MAYBE_FPUTS("Not enough bytes to fuzz\n", ZYAN_STDERR);
        return EXIT_SUCCESS;
    }
    control_block.string[ZYAN_ARRAY_LENGTH(control_block.string) - 1] = 0;

    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, control_block.machine_mode,
        control_block.stack_width)))
    {
        ZYDIS_MAYBE_FPUTS("Failed to initialize decoder\n", ZYAN_STDERR);
        return EXIT_FAILURE;
    }
    for (int mode = 0; mode <= ZYDIS_DECODER_MODE_MAX_VALUE; ++mode)
    {
        if (!ZYAN_SUCCESS(ZydisDecoderEnableMode(&decoder, (ZydisDecoderMode)mode,
            control_block.decoder_mode[mode] ? 1 : 0)))
        {
            ZYDIS_MAYBE_FPUTS("Failed to adjust decoder-mode\n", ZYAN_STDERR);
            return EXIT_FAILURE;
        }
    }

    ZydisFormatter formatter;
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, control_block.formatter_style)))
    {
        ZYDIS_MAYBE_FPUTS("Failed to initialize formatter\n", ZYAN_STDERR);
        return EXIT_FAILURE;
    }
    for (int prop = 0; prop <= ZYDIS_FORMATTER_PROP_MAX_VALUE; ++prop)
    {
        switch (prop)
        {
        case ZYDIS_FORMATTER_PROP_DEC_PREFIX:
        case ZYDIS_FORMATTER_PROP_DEC_SUFFIX:
        case ZYDIS_FORMATTER_PROP_HEX_PREFIX:
        case ZYDIS_FORMATTER_PROP_HEX_SUFFIX:
            control_block.formatter_properties[prop] =
                control_block.formatter_properties[prop] ? (ZyanUPointer)&control_block.string : 0;
            break;
        default:
            break;
        }
        if (!ZYAN_SUCCESS(ZydisFormatterSetProperty(&formatter, (ZydisFormatterProperty)prop,
            control_block.formatter_properties[prop])))
        {
            ZYDIS_MAYBE_FPUTS("Failed to set formatter-attribute\n", ZYAN_STDERR);
            return EXIT_FAILURE;
        }
    }

    ZyanU8 buffer[32];
    ZyanUSize input_len = read_fn(stream_ctx, buffer, sizeof(buffer));
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    // Fuzz decoder.
    ZyanStatus status = ZydisDecoderDecodeFull(&decoder, buffer, input_len, &instruction, operands);
    if (!ZYAN_SUCCESS(status))
    {
        return EXIT_FAILURE;
    }

    ZydisValidateEnumRanges(&instruction, operands, instruction.operand_count);

    // Fuzz formatter.
    char format_buffer[256];
    // Allow the control block to artificially restrict the buffer size.
    ZyanUSize output_len = ZYAN_MIN(sizeof(format_buffer), control_block.formatter_max_len);
    ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
        instruction.operand_count_visible, format_buffer, output_len, control_block.u64, ZYAN_NULL);

    // Fuzz tokenizer.
    const ZydisFormatterToken* token;
    status = ZydisFormatterTokenizeInstruction(&formatter, &instruction, operands,
        instruction.operand_count_visible, format_buffer, output_len, control_block.u64, &token,
        ZYAN_NULL);

    // Walk tokens.
    while (ZYAN_SUCCESS(status))
    {
        ZydisTokenType type;
        ZyanConstCharPointer value;
        if (!ZYAN_SUCCESS(status = ZydisFormatterTokenGetValue(token, &type, &value)))
        {
            ZYDIS_MAYBE_FPUTS("Failed to get token value\n", ZYAN_STDERR);
            break;
        }

        status = ZydisFormatterTokenNext(&token);
    }

    if (instruction.operand_count_visible > 0)
    {
        // Fuzz single operand formatting. We reuse rt-address for operand selection.
        // It's casted to u8 because modulo is way cheaper on that.
        ZyanU8 op_idx = (ZyanU8)control_block.u64 % instruction.operand_count_visible;
        const ZydisDecodedOperand* op = &operands[op_idx];

        ZydisFormatterFormatOperand(&formatter, &instruction, op, format_buffer, output_len,
            control_block.u64, ZYAN_NULL);

        // Fuzz single operand tokenization.
        ZydisFormatterTokenizeOperand(&formatter, &instruction, op, format_buffer, output_len,
            control_block.u64, &token, ZYAN_NULL);

        // Address translation helper.
        ZyanU64 abs_addr;
        ZydisCalcAbsoluteAddress(&instruction, op, control_block.u64, &abs_addr);
    }

    // Mnemonic helpers.
    ZydisMnemonicGetString((ZydisMnemonic)control_block.u64);
    ZydisMnemonicGetStringWrapped((ZydisMnemonic)control_block.u64);

    // Instruction segment helper.
#   ifndef ZYDIS_DISABLE_SEGMENT
    ZydisInstructionSegments segments;
    ZydisGetInstructionSegments(&instruction, &segments);
#   endif

    // Feature enable check helper.
    ZydisIsFeatureEnabled((ZydisFeature)control_block.u64);

    // Register helpers.
    ZydisRegisterEncode((ZydisRegisterClass)(control_block.u64 >> 8), (ZyanU8)control_block.u64);
    ZydisRegisterGetId((ZydisRegister)control_block.u64);
    ZydisRegisterGetClass((ZydisRegister)control_block.u64);
    ZydisRegisterGetWidth(control_block.machine_mode, (ZydisRegister)control_block.u64);
    ZydisRegisterGetLargestEnclosing(control_block.machine_mode, (ZydisRegister)control_block.u64);
    ZydisRegisterGetString((ZydisRegister)control_block.u64);
    ZydisRegisterGetStringWrapped((ZydisRegister)control_block.u64);
    ZydisRegisterClassGetWidth(control_block.machine_mode, (ZydisRegisterClass)control_block.u64);

    return EXIT_SUCCESS;
}

/* ============================================================================================== */
