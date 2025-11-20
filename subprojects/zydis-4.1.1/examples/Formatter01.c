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
 * Demonstrates basic hooking functionality of the `ZydisFormatter` class by implementing
 * a custom symbol-resolver.
 */

#include <inttypes.h>
#include <Zycore/Format.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>

/* ============================================================================================== */
/* Enums and Types                                                                                */
/* ============================================================================================== */

/**
 * Defines the `ZydisSymbol` struct.
 */
typedef struct ZydisSymbol_
{
    /**
     * The symbol address.
     */
    ZyanU64 address;
    /**
     * The symbol name.
     */
    const char* name;
} ZydisSymbol;

/* ============================================================================================== */
/* Static data                                                                                    */
/* ============================================================================================== */

/**
 * A static symbol table with some dummy symbols.
 */
static const ZydisSymbol SYMBOL_TABLE[3] =
{
    { 0x007FFFFFFF401000, "SomeModule.EntryPoint"   },
    { 0x007FFFFFFF530040, "SomeModule.SomeData"     },
    { 0x007FFFFFFF401100, "SomeModule.SomeFunction" }
};

/* ============================================================================================== */
/* Hook callbacks                                                                                 */
/* ============================================================================================== */

ZydisFormatterFunc default_print_address_absolute;

static ZyanStatus ZydisFormatterPrintAddressAbsolute(const ZydisFormatter* formatter,
    ZydisFormatterBuffer* buffer, ZydisFormatterContext* context)
{
    ZyanU64 address;
    ZYAN_CHECK(ZydisCalcAbsoluteAddress(context->instruction, context->operand,
        context->runtime_address, &address));

    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(SYMBOL_TABLE); ++i)
    {
        if (SYMBOL_TABLE[i].address == address)
        {
            ZYAN_CHECK(ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_SYMBOL));
            ZyanString* string;
            ZYAN_CHECK(ZydisFormatterBufferGetString(buffer, &string));
            return ZyanStringAppendFormat(string, "<%s>", SYMBOL_TABLE[i].name);
        }
    }

    return default_print_address_absolute(formatter, buffer, context);
}

/* ============================================================================================== */
/* Helper functions                                                                               */
/* ============================================================================================== */

static void DisassembleBuffer(ZydisDecoder* decoder, ZyanU8* data, ZyanUSize length)
{
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);

    // Replace the `ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS` function that formats the absolute
    // addresses
    default_print_address_absolute = (ZydisFormatterFunc)&ZydisFormatterPrintAddressAbsolute;
    ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS,
        (const void**)&default_print_address_absolute);

    ZyanU64 runtime_address = 0x007FFFFFFF400000;

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    char buffer[256];

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, data, length, &instruction, operands)))
    {
        ZYAN_PRINTF("%016" PRIX64 "  ", runtime_address);

        // We have to pass a `runtime_address` different to `ZYDIS_RUNTIME_ADDRESS_NONE` to
        // enable printing of absolute addresses
        ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
            instruction.operand_count_visible, &buffer[0], sizeof(buffer), runtime_address,
            ZYAN_NULL);
        ZYAN_PRINTF(" %s\n", &buffer[0]);

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
        0x48, 0x8B, 0x05, 0x39, 0x00, 0x13, 0x00, // mov rax, qword ptr ds:[<SomeModule.SomeData>]
        0x50,                                     // push rax
        0xFF, 0x15, 0xF2, 0x10, 0x00, 0x00,       // call qword ptr ds:[<SomeModule.SomeFunction>]
        0x85, 0xC0,                               // test eax, eax
        0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,       // jz 0x007FFFFFFF400016
        0xE9, 0xE5, 0x0F, 0x00, 0x00              // jmp <SomeModule.EntryPoint>
    };

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    DisassembleBuffer(&decoder, &data[0], sizeof(data));

    return 0;
}

/* ============================================================================================== */
