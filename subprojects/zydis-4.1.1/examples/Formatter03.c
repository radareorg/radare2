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
 * Demonstrates the tokenizing feature of the `ZydisFormatter` class.
 */

#include <inttypes.h>
#include <Zycore/Format.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>

/* ============================================================================================== */
/* Static data                                                                                    */
/* ============================================================================================== */

static const char* const TOKEN_TYPES[] =
{
    "INVALID          ",
    "WHITESPACE       ",
    "DELIMITER        ",
    "PARENTHESIS_OPEN ",
    "PARENTHESIS_CLOSE",
    "PREFIX           ",
    "MNEMONIC         ",
    "REGISTER         ",
    "ADDRESS_ABS      ",
    "ADDRESS_REL      ",
    "DISPLACEMENT     ",
    "IMMEDIATE        ",
    "TYPECAST         ",
    "DECORATOR        ",
    "SYMBOL           "
};

/* ============================================================================================== */
/* Helper functions                                                                               */
/* ============================================================================================== */

static void DisassembleBuffer(ZydisDecoder* decoder, ZyanU8* data, ZyanUSize length)
{
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);

    ZyanU64 runtime_address = 0x007FFFFFFF400000;

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    char buffer[256];

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, data, length, &instruction, operands)))
    {
        const ZydisFormatterToken* token;
        if (ZYAN_SUCCESS(ZydisFormatterTokenizeInstruction(&formatter, &instruction, operands,
            instruction.operand_count_visible , &buffer[0], sizeof(buffer), runtime_address,
            &token, ZYAN_NULL)))
        {
            ZydisTokenType token_type;
            ZyanConstCharPointer token_value = ZYAN_NULL;
            while (token)
            {
                ZydisFormatterTokenGetValue(token, &token_type, &token_value);
                printf("ZYDIS_TOKEN_%17s (%02X): \"%s\"\n", TOKEN_TYPES[token_type], token_type,
                    token_value);
                if (!ZYAN_SUCCESS(ZydisFormatterTokenNext(&token)))
                {
                    token = ZYAN_NULL;
                }
            }
        }

        data += instruction.length;
        length -= instruction.length;
        runtime_address += instruction.length;
    }
}

/* ============================================================================================== */
/* Entry point                                                                                    */
/* ============================================================================================== */

int main(void)
{
    if (ZydisGetVersion() != ZYDIS_VERSION)
    {
        fputs("Invalid zydis version\n", ZYAN_STDERR);
        return EXIT_FAILURE;
    }

    ZyanU8 data[] =
    {
        // vcmpps k2 {k7}, zmm2, dword ptr ds:[rax + rbx*4 + 0x100] {1to16}, 0x0F
        0x62, 0xF1, 0x6C, 0x5F, 0xC2, 0x54, 0x98, 0x40, 0x0F
    };

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    DisassembleBuffer(&decoder, &data[0], sizeof(data));

    return 0;
}

/* ============================================================================================== */
