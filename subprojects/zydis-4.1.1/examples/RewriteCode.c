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
 * Example that takes raw instruction bytes as command line argument, decoding the instruction and
 * changing a range of things about it before encoding it again, printing the new instruction bytes.
 *
 * `jz` instructions are rewritten to `jnz`, `add` is replaced with `sub`. Immediate operand
 * constants are changed to `0x42` and the displacement in memory operands is changed to `0x1337`.
 *
 * The example always consumes and generates code in 64-bit mode.
 */

#include <Zydis/Zydis.h>
#include <Zycore/LibC.h>
#include <Zycore/API/Memory.h>

#include <inttypes.h>

/* ============================================================================================== */
/* Entry point                                                                                    */
/* ============================================================================================== */

static void ExpectSuccess(ZyanStatus status)
{
    if (ZYAN_FAILED(status))
    {
        fprintf(stderr, "Something failed: 0x%08X\n", status);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage example: %s e9 12 33 44 55", argc > 0 ? argv[0] : "<binary>");
        exit(EXIT_FAILURE);
    }

    // Parse arguments.
    uint8_t bytes[ZYDIS_MAX_INSTRUCTION_LENGTH];
    size_t num_bytes = ZYAN_MIN(ZYDIS_MAX_INSTRUCTION_LENGTH, argc - 1);
    for (size_t i = 0; i < num_bytes; ++i)
    {
        unsigned long int val = strtoul(argv[i + 1], NULL, 16);
        if (errno == ERANGE)
        {
            fprintf(stderr, "Error: Received non-hex argument: %s", argv[i + 1]);
            exit(EXIT_FAILURE);
        }
        if (val > UINT8_MAX)
        {
            fprintf(stderr, "Error: Argument value too large: %s. Expected byte.", argv[i + 1]);
            exit(EXIT_FAILURE);
        }

        bytes[i] = (uint8_t)val;
    }

    // Initialize decoder in X86-64 mode.
    ZydisDecoder decoder;
    ExpectSuccess(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64));

    // Attempt to decode the given bytes as an X86-64 instruction.
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanStatus status = ZydisDecoderDecodeFull(&decoder, bytes, num_bytes, &instr, operands);
    if (ZYAN_FAILED(status))
    {
        fprintf(stderr, "Failed to decode instruction: %02" PRIx32, status);
        exit(EXIT_FAILURE);
    }

    // Initialize the formatter.
    ZydisFormatter fmt;
    ExpectSuccess(ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL));

    // Format & print the original instruction.
    char fmt_buf[256];
    ExpectSuccess(ZydisFormatterFormatInstruction(&fmt, &instr, operands,
        instr.operand_count_visible, fmt_buf, sizeof(fmt_buf), 0, NULL));
    printf("Original instruction: %s\n", fmt_buf);

    // Create an encoder request from the previously decoded instruction.
    ZydisEncoderRequest enc_req;
    ExpectSuccess(ZydisEncoderDecodedInstructionToEncoderRequest(&instr, operands,
        instr.operand_count_visible, &enc_req));

    // Now, change some things about the instruction!

    // Change `jz` -> `jnz` and `add` -> `sub`.
    switch (enc_req.mnemonic)
    {
        case ZYDIS_MNEMONIC_ADD:
            enc_req.mnemonic = ZYDIS_MNEMONIC_SUB;
            break;
        case ZYDIS_MNEMONIC_JZ:
            enc_req.mnemonic = ZYDIS_MNEMONIC_JNZ;
            break;
        default:
            // Don't change other instructions.
            break;
    }

    // Walk the operand list and look for things to change.
    for (int i = 0; i < enc_req.operand_count; ++i)
    {
        ZydisEncoderOperand *op = &enc_req.operands[i];

        switch (op->type)
        {
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            // For immediate operands, change the constant to `0x42`.
            op->imm.u = 0x42;
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            // For memory operands, change the displacement to `0x1337` and the scale to `2`.
            op->mem.displacement = 0x1337;
            break;
        default:
            // Any other operands remain unchanged.
            break;
        }
    }

    // Encode the instruction back to raw bytes.
    uint8_t new_bytes[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize new_instr_length = sizeof(new_bytes);
    ExpectSuccess(ZydisEncoderEncodeInstruction(&enc_req, new_bytes, &new_instr_length));

    // Decode and print the new instruction. We re-use the old buffers.
    ExpectSuccess(ZydisDecoderDecodeFull(&decoder, new_bytes, new_instr_length, &instr,
        operands));
    ExpectSuccess(ZydisFormatterFormatInstruction(&fmt, &instr, operands,
        instr.operand_count_visible, fmt_buf, sizeof(fmt_buf), 0, NULL));
    printf("New instruction:      %s\n", fmt_buf);

    // Print the new instruction as hex-bytes.
    printf("New raw bytes:        ");
    for (ZyanUSize i = 0; i < new_instr_length; ++i)
    {
        printf("%02" PRIx8 " ", new_bytes[i]);
    }
    putchar('\n');
}

/* ============================================================================================== */
