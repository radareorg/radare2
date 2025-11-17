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
 * Demonstrates basic hooking functionality of the `ZydisFormatter` class and the ability
 * to completely omit specific operands.
 *
 * This example demonstrates the hooking functionality of the `ZydisFormatter` class by
 * rewriting the mnemonics of `(V)CMPPS` and `(V)CMPPD` to their corresponding alias-forms (based
 * on the condition encoded in the immediate operand).
 */

#include <inttypes.h>
#include <Zycore/Format.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>

/* ============================================================================================== */
/* Static data                                                                                    */
/* ============================================================================================== */

/**
 * Static array with the condition-code strings.
 */
static const char* const CONDITION_CODE_STRINGS[0x20] =
{
    /*00*/ "eq",
    /*01*/ "lt",
    /*02*/ "le",
    /*03*/ "unord",
    /*04*/ "neq",
    /*05*/ "nlt",
    /*06*/ "nle",
    /*07*/ "ord",
    /*08*/ "eq_uq",
    /*09*/ "nge",
    /*0A*/ "ngt",
    /*0B*/ "false",
    /*0C*/ "oq",
    /*0D*/ "ge",
    /*0E*/ "gt",
    /*0F*/ "true",
    /*10*/ "eq_os",
    /*11*/ "lt_oq",
    /*12*/ "le_oq",
    /*13*/ "unord_s",
    /*14*/ "neq_us",
    /*15*/ "nlt_uq",
    /*16*/ "nle_uq",
    /*17*/ "ord_s",
    /*18*/ "eq_us",
    /*19*/ "nge_uq",
    /*1A*/ "ngt_uq",
    /*1B*/ "false_os",
    /*1C*/ "neq_os",
    /*1D*/ "ge_oq",
    /*1E*/ "gt_oq",
    /*1F*/ "true_us"
};

/* ============================================================================================== */
/* Enums and Types                                                                                */
/* ============================================================================================== */

/**
 * Custom user data struct for the formatter.
 */
typedef struct ZydisCustomUserData_
{
    ZyanBool omit_immediate;
} ZydisCustomUserData;

/* ============================================================================================== */
/* Hook callbacks                                                                                 */
/* ============================================================================================== */

ZydisFormatterFunc default_print_mnemonic;

static ZyanStatus ZydisFormatterPrintMnemonic(const ZydisFormatter* formatter,
    ZydisFormatterBuffer* buffer, ZydisFormatterContext* context)
{
    // We use the user-data to pass data to the `ZydisFormatterFormatOperandImm` function
    ZydisCustomUserData* user_data = (ZydisCustomUserData*)context->user_data;
    user_data->omit_immediate = ZYAN_TRUE;

    // Rewrite the instruction-mnemonic for the given instructions
    if (context->instruction->operand_count_visible &&
        context->operands[context->instruction->operand_count_visible - 1].type ==
        ZYDIS_OPERAND_TYPE_IMMEDIATE)
    {
        // Retrieve the `ZyanString` instance of the formatter-buffer
        ZyanString* string;
        ZYAN_CHECK(ZydisFormatterBufferGetString(buffer, &string));

        const ZyanU8 condition_code = (ZyanU8)context->operands[
            context->instruction->operand_count_visible - 1].imm.value.u;
        switch (context->instruction->mnemonic)
        {
        case ZYDIS_MNEMONIC_CMPPS:
            if (condition_code < 0x08)
            {
                ZYAN_CHECK(ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_MNEMONIC));
                return ZyanStringAppendFormat(string, "cmp%sps",
                    CONDITION_CODE_STRINGS[condition_code]);
            }
            break;
        case ZYDIS_MNEMONIC_CMPPD:
            if (condition_code < 0x08)
            {
                ZYAN_CHECK(ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_MNEMONIC));
                return ZyanStringAppendFormat(string, "cmp%spd",
                    CONDITION_CODE_STRINGS[condition_code]);
            }
            break;
        case ZYDIS_MNEMONIC_VCMPPS:
            if (condition_code < 0x20)
            {
                ZYAN_CHECK(ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_MNEMONIC));
                return ZyanStringAppendFormat(string, "vcmp%sps",
                    CONDITION_CODE_STRINGS[condition_code]);
            }
            break;
        case ZYDIS_MNEMONIC_VCMPPD:
            if (condition_code < 0x20)
            {
                ZYAN_CHECK(ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_MNEMONIC));
                return ZyanStringAppendFormat(string, "vcmp%spd",
                    CONDITION_CODE_STRINGS[condition_code]);
            }
            break;
        default:
            break;
        }
    }

    // We did not rewrite the instruction-mnemonic. Signal the `ZydisFormatterFormatOperandImm`
    // function not to omit the operand
    user_data->omit_immediate = ZYAN_FALSE;

    // Default mnemonic printing
    return default_print_mnemonic(formatter, buffer, context);
}

/* ---------------------------------------------------------------------------------------------- */

ZydisFormatterFunc default_format_operand_imm;

static ZyanStatus ZydisFormatterFormatOperandIMM(const ZydisFormatter* formatter,
    ZydisFormatterBuffer* buffer, ZydisFormatterContext* context)
{
    // The `ZydisFormatterFormatMnemonic` sinals us to omit the immediate (condition-code)
    // operand, because it got replaced by the alias-mnemonic
    const ZydisCustomUserData* user_data = (ZydisCustomUserData*)context->user_data;
    if (user_data->omit_immediate)
    {
        return ZYDIS_STATUS_SKIP_TOKEN;
    }

    // Default immediate formatting
    return default_format_operand_imm(formatter, buffer, context);
}

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
/* Helper functions                                                                               */
/* ============================================================================================== */

static void DisassembleBuffer(ZydisDecoder* decoder, ZyanU8* data, ZyanUSize length,
    ZyanBool install_hooks)
{
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);

    if (install_hooks)
    {
        default_print_mnemonic = (ZydisFormatterFunc)&ZydisFormatterPrintMnemonic;
        ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_MNEMONIC,
            (const void**)&default_print_mnemonic);
        default_format_operand_imm = (ZydisFormatterFunc)&ZydisFormatterFormatOperandIMM;
        ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_FORMAT_OPERAND_IMM,
            (const void**)&default_format_operand_imm);
    }

    ZyanU64 runtime_address = 0x007FFFFFFF400000;

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZydisCustomUserData user_data;
    char buffer[256];

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, data, length, &instruction, operands)))
    {
        ZYAN_PRINTF("%016" PRIX64 "  ", runtime_address);

        ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
            instruction.operand_count_visible, &buffer[0], sizeof(buffer), runtime_address,
            &user_data);
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
        // nop
        0x90,

        // cmpps xmm1, xmm4, 0x03
        0x0F, 0xC2, 0xCC, 0x03,

        // vcmppd xmm1, xmm2, xmm3, 0x17
        0xC5, 0xE9, 0xC2, 0xCB, 0x17,

        // vcmpps k2 {k7}, zmm2, dword ptr ds:[rax + rbx*4 + 0x100] {1to16}, 0x0F
        0x62, 0xF1, 0x6C, 0x5F, 0xC2, 0x54, 0x98, 0x40, 0x0F
    };

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    DisassembleBuffer(&decoder, &data[0], sizeof(data), ZYAN_FALSE);
    ZYAN_PUTS("");
    DisassembleBuffer(&decoder, &data[0], sizeof(data), ZYAN_TRUE);

    return 0;
}

/* ============================================================================================== */
