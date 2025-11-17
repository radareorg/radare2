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
 * Disassembles a given hex-buffer and prints detailed information about the decoded
 * instruction, the operands and additional attributes.
 */

#include "ZydisToolsShared.h"

#include <inttypes.h>

#include <Zycore/API/Terminal.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>

/* ============================================================================================== */
/* Colors                                                                                         */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* Configuration                                                                                  */
/* ---------------------------------------------------------------------------------------------- */

#define COLOR_HEADER        ZYAN_VT100SGR_FG_DEFAULT
#define COLOR_HEADER_TITLE  ZYAN_VT100SGR_FG_CYAN
#define COLOR_VALUE_LABEL   ZYAN_VT100SGR_FG_DEFAULT
#define COLOR_VALUE_R       ZYAN_VT100SGR_FG_BRIGHT_RED
#define COLOR_VALUE_G       ZYAN_VT100SGR_FG_BRIGHT_GREEN
#define COLOR_VALUE_B       ZYAN_VT100SGR_FG_BRIGHT_BLUE

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
/* Helper functions                                                                               */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* General                                                                                        */
/* ---------------------------------------------------------------------------------------------- */

/**
 * Returns the action string for a specific CPU/FPU flag.
 *
 * @param accessed_flags    A pointer to the `ZydisAccessedFlags` struct.
 * @param flag              The number of the flag.
 *
 * @return The action string for the requested flag, or `ZYAN_NULL`.
 */
static const char* GetAccessedFlagActionString(const ZydisAccessedFlags* accessed_flags,
    ZyanU8 flag)
{
    ZYAN_ASSERT(flag < 32);

    const char* result = ZYAN_NULL;

    if (accessed_flags->tested & (1 << flag))
    {
        result = "T";
    }
    if (accessed_flags->modified & (1 << flag))
    {
        result = (result == ZYAN_NULL) ? "M" : "T_M";
        return result;
    }

    if (accessed_flags->set_0 & (1 << flag))
    {
        return "0";
    }
    if (accessed_flags->set_1 & (1 << flag))
    {
        return "1";
    }
    if (accessed_flags->undefined & (1 << flag))
    {
        return "U";
    }

    return result;
}

/* ---------------------------------------------------------------------------------------------- */
/* Text output                                                                                    */
/* ---------------------------------------------------------------------------------------------- */

/**
 * Prints a section header.
 *
 * @param   name    The section name.
 */
static void PrintSectionHeader(const char* name)
{
    ZYAN_ASSERT(ZYAN_STRLEN(name) <= 8);
    ZYAN_PRINTF("%s== [ %s%8s%s ] ==============================================================" \
        "==============================%s\n",
        CVT100_OUT(COLOR_HEADER), CVT100_OUT(COLOR_HEADER_TITLE), name, CVT100_OUT(COLOR_HEADER),
        CVT100_OUT(COLOR_DEFAULT));
}

/**
 * Prints a value label.
 *
 * @param   name    The value name.
 */
static void PrintValueLabel(const char* name)
{
    ZYAN_ASSERT(ZYAN_STRLEN(name) <= 11);
    ZYAN_PRINTF("%s%11s:%s ", CVT100_OUT(COLOR_VALUE_LABEL), name, CVT100_OUT(COLOR_DEFAULT));
}

/**
 * Prints a formatted value using red color.
 *
 * @param   name    The value name.
 * @param   format  The format string.
 * @param   ...     The format arguments.
 */
#define PRINT_VALUE_R(name, format, ...) \
    PrintValueLabel(name); \
    ZYAN_PRINTF("%s" format "%s\n", CVT100_OUT(COLOR_VALUE_R), __VA_ARGS__, \
        CVT100_OUT(COLOR_DEFAULT));

/**
 * Prints a formatted value using green color.
 *
 * @param   name    The value name.
 * @param   format  The format string.
 * @param   ...     The format arguments.
 */
#define PRINT_VALUE_G(name, format, ...) \
    PrintValueLabel(name); \
    ZYAN_PRINTF("%s" format "%s\n", CVT100_OUT(COLOR_VALUE_G), __VA_ARGS__, \
        CVT100_OUT(COLOR_DEFAULT));

/**
 * Prints a formatted value using blue color.
 *
 * @param   name    The value name.
 * @param   format  The format string.
 * @param   ...     The format arguments.
 */
#define PRINT_VALUE_B(name, format, ...) \
    PrintValueLabel(name); \
    ZYAN_PRINTF("%s" format "%s\n", CVT100_OUT(COLOR_VALUE_B), __VA_ARGS__, \
        CVT100_OUT(COLOR_DEFAULT));

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
/* Print functions                                                                                */
/* ============================================================================================== */

#if !defined(ZYDIS_DISABLE_SEGMENT)

/**
 * Prints instruction segments (parts).
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 * @param   buffer      The buffer that contains the instruction bytes.
 * @param   print_hints Controls the printing of descriptive hints.
 */
static void PrintSegments(const ZydisDecodedInstruction* instruction, const ZyanU8* buffer,
    ZyanBool print_hints)
{
    ZydisInstructionSegments segments;
    ZydisGetInstructionSegments(instruction, &segments);

    struct
    {
        ZyanU8 pos;
        const char* color;
        const char* name;
    } print_info[ZYAN_ARRAY_LENGTH(segments.segments)];

    ZyanU8 pos = 0;
    ZyanU8 imm = 0;
    for (ZyanU8 i = 0; i < segments.count; ++i)
    {
        print_info[i].pos = pos;

        switch (segments.segments[i].type)
        {
        case ZYDIS_INSTR_SEGMENT_PREFIXES:
            print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_RED);
            print_info[i].name  = "PREFIXES";
            break;
        case ZYDIS_INSTR_SEGMENT_REX:
            print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_MAGENTA);
            print_info[i].name  = "REX";
            break;
        case ZYDIS_INSTR_SEGMENT_XOP:
            print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_MAGENTA);
            print_info[i].name  = "XOP";
            break;
        case ZYDIS_INSTR_SEGMENT_VEX:
            print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_MAGENTA);
            print_info[i].name  = "VEX";
            break;
        case ZYDIS_INSTR_SEGMENT_EVEX:
            print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_MAGENTA);
            print_info[i].name  = "EVEX";
            break;
        case ZYDIS_INSTR_SEGMENT_MVEX:
            print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_MAGENTA);
            print_info[i].name  = "MVEX";
            break;
        case ZYDIS_INSTR_SEGMENT_OPCODE:
            print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_BLUE);
            print_info[i].name  = "OPCODE";
            break;
        case ZYDIS_INSTR_SEGMENT_MODRM:
            print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_CYAN);
            print_info[i].name  = "MODRM";
            break;
        case ZYDIS_INSTR_SEGMENT_SIB:
            print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_GREEN);
            print_info[i].name  = "SIB";
            break;
        case ZYDIS_INSTR_SEGMENT_DISPLACEMENT:
            print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_YELLOW);
            print_info[i].name  = "DISP";
            break;
        case ZYDIS_INSTR_SEGMENT_IMMEDIATE:
            if (imm == 0)
            {
                print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_YELLOW);
                imm = 1;
            }
            else
            {
                print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_YELLOW);
            }
            print_info[i].name = "IMM";
            break;
        default:
            ZYAN_UNREACHABLE;
        }

        ZYAN_PRINTF("%s", print_info[i].color);
        for (int j = 0; j < segments.segments[i].size; ++j)
        {
            if (segments.segments[i].type == ZYDIS_INSTR_SEGMENT_PREFIXES)
            {
                ZYAN_ASSERT(segments.segments[i].size <= instruction->raw.prefix_count);
                switch (instruction->raw.prefixes[j].type)
                {
                case ZYDIS_PREFIX_TYPE_IGNORED:
                    ZYAN_PRINTF("%s%02X%s ", CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_BLACK),
                        buffer[segments.segments[i].offset + j], print_info[i].color);
                    pos += 3;
                    break;
                case ZYDIS_PREFIX_TYPE_EFFECTIVE:
                    pos += (ZyanU8)ZYAN_PRINTF("%02X ", buffer[segments.segments[i].offset + j]);
                    break;
                case ZYDIS_PREFIX_TYPE_MANDATORY:
                    ZYAN_PRINTF("%s%02X%s ",
                        CVT100_OUT(ZYAN_VT100SGR_FG_CYAN),
                        buffer[segments.segments[i].offset + j], print_info[i].color);
                    pos += 3;
                    break;
                default:
                    ZYAN_UNREACHABLE;
                }
            }
            else
            {
                pos += (ZyanU8)ZYAN_PRINTF("%02X ", buffer[segments.segments[i].offset + j]);
            }
        }
    }
    ZYAN_PRINTF("%s\n", CVT100_OUT(COLOR_DEFAULT));

    if (!print_hints)
    {
        return;
    }

    for (ZyanU8 i = 0; i < segments.count; ++i)
    {
        ZyanU8 j = 0;
        ZyanU8 k = 0;
        while (j <= print_info[segments.count - i - 1].pos)
        {
            if (j == print_info[k].pos)
            {
                ZYAN_PRINTF("%s:", print_info[k].color);
                ++k;
            }
            else
            {
                ZYAN_PRINTF(" ");
            }
            ++j;
        }
        ZYAN_PRINTF("..%s%s\n", print_info[segments.count - i - 1].color,
            print_info[segments.count - i - 1].name);
    }

    ZYAN_PRINTF(CVT100_OUT(COLOR_DEFAULT));
}

#endif

#if !defined(ZYDIS_DISABLE_ENCODER)

/**
 * Prints a size optimized form of the input instruction.
 *
 * @param decoder       A pointer to the `ZydisDecoder` instance.
 * @param instruction   A pointer to the `ZydisDecodedInstruction` struct.
 * @param operands      A pointer to the `operands` array.
 * @param operand_count The length of the `operands` array.
 */
static void PrintSizeOptimizedForm(const ZydisDecoder* decoder,
    const ZydisDecodedInstruction* instruction, const ZydisDecodedOperand* operands,
    ZyanU8 operand_count)
{
    ZydisEncoderRequest request;
    ZyanStatus status = ZydisEncoderDecodedInstructionToEncoderRequest(instruction, operands,
        operand_count, &request);
    if (!ZYAN_SUCCESS(status))
    {
        PrintStatusError(status, "Failed to craft encoder request");
        exit(status);
    }

    ZyanU8 data[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize len = sizeof(data);
    status = ZydisEncoderEncodeInstruction(&request, data, &len);
    if (!ZYAN_SUCCESS(status))
    {
        PrintStatusError(status, "Could not encode instruction");
        exit(status);
    }

    ZydisDecodedInstruction new_instruction;
    status = ZydisDecoderDecodeInstruction(decoder, ZYAN_NULL, &data, len, &new_instruction);
    if (!ZYAN_SUCCESS(status))
    {
        PrintStatusError(status, "Could not decode instruction");
        exit(status);
    }

#if !defined(ZYDIS_DISABLE_SEGMENT)
    PrintSegments(&new_instruction, &data[0], ZYAN_FALSE);
#endif
}

#endif

/**
 * Prints instruction operands info.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 * @param   operands    A pointer to the first `ZydisDecodedOperand` struct of the instruction.
 */
static void PrintOperands(const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands)
{
    PrintSectionHeader("OPERANDS");
    ZYAN_PRINTF("%s##       TYPE  VISIBILITY  ACTION      ENCODING   SIZE  NELEM  ELEMSZ  ELEMTY" \
        "PE                        VALUE%s\n", CVT100_OUT(COLOR_HEADER), CVT100_OUT(COLOR_DEFAULT));
    ZYAN_PRINTF("%s--  ---------  ----------  ------  ------------   ----  -----  ------  ------" \
        "--  ---------------------------%s\n", CVT100_OUT(COLOR_HEADER), CVT100_OUT(COLOR_DEFAULT));

    ZyanU8 imm_id = 0;
    for (ZyanU8 i = 0; i < instruction->operand_count; ++i)
    {
        static const char* strings_operand_type[] =
        {
            "UNUSED",
            "REGISTER",
            "MEMORY",
            "POINTER",
            "IMMEDIATE"
        };
        ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_operand_type) == ZYDIS_OPERAND_TYPE_MAX_VALUE + 1);

        static const char* strings_operand_visibility[] =
        {
            "INVALID",
            "EXPLICIT",
            "IMPLICIT",
            "HIDDEN"
        };
        ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_operand_visibility) == ZYDIS_OPERAND_VISIBILITY_MAX_VALUE + 1);

        static const char* strings_operand_actions[] =
        {
            "NONE",  // 0 0 0 0
            "R",     // 0 0 0 1
            "W",     // 0 0 1 0
            "RW",    // 0 0 1 1
            "CR",    // 0 1 0 0
            "-",     // 0 1 0 1
            "CRW",   // 0 1 1 0
            "-",     // 0 1 1 1
            "CW",    // 1 0 0 0
            "RCW",   // 1 0 0 1
            "-",     // 1 0 1 0
            "-",     // 1 0 1 1
            "CRCW",  // 1 1 0 0
            "-",     // 1 1 0 1
            "-"      // 1 1 1 1
        };

        static const char* strings_element_type[] =
        {
            "INVALID",
            "STRUCT",
            "UINT",
            "INT",
            "FLOAT16",
            "FLOAT32",
            "FLOAT64",
            "FLOAT80",
            "BFLOAT16",
            "LONGBCD",
            "CC"
        };
        ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_element_type) == ZYDIS_ELEMENT_TYPE_MAX_VALUE + 1);

        static const char* strings_operand_encoding[] =
        {
            "NONE",
            "MODRM_REG",
            "MODRM_RM",
            "OPCODE",
            "NDSNDD",
            "IS4",
            "MASK",
            "DISP8",
            "DISP16",
            "DISP32",
            "DISP64",
            "DISP16_32_64",
            "DISP32_32_64",
            "DISP16_32_32",
            "UIMM8",
            "UIMM16",
            "UIMM32",
            "UIMM64",
            "UIMM16_32_64",
            "UIMM32_32_64",
            "UIMM16_32_32",
            "SIMM8",
            "SIMM16",
            "SIMM32",
            "SIMM64",
            "SIMM16_32_64",
            "SIMM32_32_64",
            "SIMM16_32_32",
            "JIMM8",
            "JIMM16",
            "JIMM32",
            "JIMM64",
            "JIMM16_32_64",
            "JIMM32_32_64",
            "JIMM16_32_32"
        };
        ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_operand_encoding) == ZYDIS_OPERAND_ENCODING_MAX_VALUE + 1);

        static const char* strings_memop_type[] =
        {
            "INVALID",
            "MEM",
            "AGEN",
            "MIB",
            "VSIB"
        };
        ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_memop_type) == ZYDIS_MEMOP_TYPE_MAX_VALUE + 1);

        ZYAN_PRINTF("%s%2d  %s%9s  %10s  %6s  %12s  %s%5d   %4d  %6d  %s%8s%s",
            CVT100_OUT(COLOR_VALUE_G),
            i,
            CVT100_OUT(COLOR_VALUE_B),
            strings_operand_type[operands[i].type],
            strings_operand_visibility[operands[i].visibility],
            strings_operand_actions[operands[i].actions],
            strings_operand_encoding[operands[i].encoding],
            CVT100_OUT(COLOR_VALUE_G),
            operands[i].size,
            operands[i].element_count,
            operands[i].element_size,
            CVT100_OUT(COLOR_VALUE_B),
            strings_element_type[operands[i].element_type],
            CVT100_OUT(COLOR_DEFAULT));
        switch (operands[i].type)
        {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            ZYAN_PRINTF("  %s%27s%s", CVT100_OUT(COLOR_VALUE_R),
                ZydisRegisterGetString(operands[i].reg.value),
                CVT100_OUT(COLOR_DEFAULT));
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            ZYAN_PRINTF("  %sTYPE  =%s%20s%s\n", CVT100_OUT(COLOR_VALUE_LABEL),
                CVT100_OUT(COLOR_VALUE_B), strings_memop_type[operands[i].mem.type],
                CVT100_OUT(COLOR_DEFAULT));
            ZYAN_PRINTF("  %s%84s =%s%20s%s\n",
                CVT100_OUT(COLOR_VALUE_LABEL), "SEG  ", CVT100_OUT(COLOR_VALUE_R),
                ZydisRegisterGetString(operands[i].mem.segment),
                CVT100_OUT(COLOR_DEFAULT));
            ZYAN_PRINTF("  %s%84s =%s%20s%s\n",
                CVT100_OUT(COLOR_VALUE_LABEL), "BASE ", CVT100_OUT(COLOR_VALUE_R),
                ZydisRegisterGetString(operands[i].mem.base),
                CVT100_OUT(COLOR_DEFAULT));
            ZYAN_PRINTF("  %s%84s =%s%20s%s\n",
                CVT100_OUT(COLOR_VALUE_LABEL), "INDEX", CVT100_OUT(COLOR_VALUE_R),
                ZydisRegisterGetString(operands[i].mem.index),
                CVT100_OUT(COLOR_DEFAULT));
            ZYAN_PRINTF("  %s%84s =%s%20d%s\n",
                CVT100_OUT(COLOR_VALUE_LABEL), "SCALE", CVT100_OUT(COLOR_VALUE_G),
                operands[i].mem.scale,
                CVT100_OUT(COLOR_DEFAULT));
            ZYAN_PRINTF("  %s%84s =  %s0x%016" PRIX64 "%s",
                CVT100_OUT(COLOR_VALUE_LABEL), "DISP ", CVT100_OUT(COLOR_VALUE_G),
                operands[i].mem.disp.value,
                CVT100_OUT(COLOR_DEFAULT));
            break;
        case ZYDIS_OPERAND_TYPE_POINTER:
            ZYAN_PRINTF("  %sSEG   =              %s0x%04" PRIX16 "%s\n",
                CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(COLOR_VALUE_G),
                operands[i].ptr.segment,
                CVT100_OUT(COLOR_DEFAULT));
            ZYAN_PRINTF("  %s%84s =          %s0x%08" PRIX32 "%s",
                CVT100_OUT(COLOR_VALUE_LABEL), "OFF  ", CVT100_OUT(COLOR_VALUE_G),
                operands[i].ptr.offset,
                CVT100_OUT(COLOR_DEFAULT));
            break;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            if (operands[i].imm.is_signed)
            {
                ZYAN_PRINTF("  %s[%s%s %s %s%2d%s] %s0x%016" PRIX64 "%s",
                    CVT100_OUT(COLOR_VALUE_LABEL),
                    CVT100_OUT(COLOR_VALUE_B),
                    operands[i].imm.is_signed ? "S" : "U",
                    operands[i].imm.is_relative ? "R" : "A",
                    CVT100_OUT(COLOR_VALUE_G),
                    instruction->raw.imm[imm_id].size,
                    CVT100_OUT(COLOR_VALUE_LABEL),
                    CVT100_OUT(COLOR_VALUE_G),
                    operands[i].imm.value.s,
                    CVT100_OUT(COLOR_DEFAULT));
            }
            else
            {
                ZYAN_PRINTF("  %s[%s%s %s %s%2d%s] %s0x%016" PRIX64 "%s",
                    CVT100_OUT(COLOR_VALUE_LABEL),
                    CVT100_OUT(COLOR_VALUE_B),
                    operands[i].imm.is_signed ? "S" : "U",
                    operands[i].imm.is_relative ? "R" : "A",
                    CVT100_OUT(COLOR_VALUE_G),
                    instruction->raw.imm[imm_id].size,
                    CVT100_OUT(COLOR_VALUE_LABEL),
                    CVT100_OUT(COLOR_VALUE_G),
                    operands[i].imm.value.u,
                    CVT100_OUT(COLOR_DEFAULT));
            }
            ++imm_id;
            break;
        default:
            ZYAN_UNREACHABLE;
        }
        ZYAN_PUTS("");
    }

    ZYAN_PRINTF("%s--  ---------  ----------  ------  ------------   ----  -----  ------  ------" \
        "--  ---------------------------%s\n", CVT100_OUT(COLOR_HEADER), CVT100_OUT(COLOR_DEFAULT));
}

/**
 * Prints instruction flags info.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 */
static void PrintFlags(const ZydisDecodedInstruction* instruction)
{
    static const char* strings_cpu_flags[] =
    {
        "CF",
        ZYAN_NULL,
        "PF",
        ZYAN_NULL,
        "AF",
        ZYAN_NULL,
        "ZF",
        "SF",
        "TF",
        "IF",
        "DF",
        "OF",
        "IOPL",
        ZYAN_NULL,
        "NT",
        ZYAN_NULL,
        "RF",
        "VM",
        "AC",
        "VIF",
        "VIP",
        "ID",
    };

    static const char* strings_fpu_flags[] =
    {
        "C0",
        "C1",
        "C2",
        "C3",
    };

    typedef struct FlagInfo_
    {
        const char* name;
        const char* action;
    } FlagInfo;

    FlagInfo flags[ZYAN_ARRAY_LENGTH(strings_cpu_flags) + ZYAN_ARRAY_LENGTH(strings_fpu_flags)];
    ZYAN_MEMSET(flags, 0, sizeof(flags));

    // CPU
    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(strings_cpu_flags); ++i)
    {
        flags[i].name = strings_cpu_flags[i];
        flags[i].action = GetAccessedFlagActionString(instruction->cpu_flags, (ZyanU8)i);
    }

    // FPU
    const ZyanUSize offset = ZYAN_ARRAY_LENGTH(strings_cpu_flags);
    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(strings_fpu_flags); ++i)
    {
        flags[offset + i].name = strings_fpu_flags[i];
        flags[offset + i].action = GetAccessedFlagActionString(instruction->fpu_flags, (ZyanU8)i);
    }

    PrintSectionHeader("FLAGS");

    PrintValueLabel("ACTIONS");

    ZyanU8 c = 0;
    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(flags); ++i)
    {
        if (flags[i].action == ZYAN_NULL)
        {
            continue;
        }
        if (c && (c % 8 == 0))
        {
            ZYAN_PRINTF("\n             ");
        }
        ++c;
        ZYAN_PRINTF("%s[%s%-4s%s: %s%-3s%s]%s ",
            CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(COLOR_VALUE_B),
            flags[i].name,
            CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(COLOR_VALUE_B),
            flags[i].action,
            CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(COLOR_DEFAULT));
    }
    ZYAN_PUTS("");

    PRINT_VALUE_G("READ", "0x%08" PRIX32, instruction->cpu_flags->tested);
    PRINT_VALUE_G("WRITTEN", "0x%08" PRIX32,
        instruction->cpu_flags->modified |
        instruction->cpu_flags->set_0 |
        instruction->cpu_flags->set_1 |
        instruction->cpu_flags->undefined);
}

/**
 * Prints instruction AVX info.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 */
static void PrintAVXInfo(const ZydisDecodedInstruction* instruction)
{
    static const char* strings_broadcast_mode[] =
    {
        "NONE",
        "1_TO_2",
        "1_TO_4",
        "1_TO_8",
        "1_TO_16",
        "1_TO_32",
        "1_TO_64",
        "2_TO_4",
        "2_TO_8",
        "2_TO_16",
        "4_TO_8",
        "4_TO_16",
        "8_TO_16"
    };
    ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_broadcast_mode) == ZYDIS_BROADCAST_MODE_MAX_VALUE + 1);

    static const char* strings_mask_mode[] =
    {
        "INVALID",
        "DISABLED",
        "MERGING",
        "ZEROING",
        "CONTROL",
        "CONTROL_ZEROING"
    };
    ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_mask_mode) == ZYDIS_MASK_MODE_MAX_VALUE + 1);

    static const char* strings_rounding_mode[] =
    {
        "DEFAULT",
        "RN",
        "RD",
        "RU",
        "RZ"
    };
    ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_rounding_mode) == ZYDIS_ROUNDING_MODE_MAX_VALUE + 1);

    static const char* strings_swizzle_mode[] =
    {
        "NONE",
        "DCBA",
        "CDAB",
        "BADC",
        "DACB",
        "AAAA",
        "BBBB",
        "CCCC",
        "DDDD"
    };
    ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_swizzle_mode) == ZYDIS_SWIZZLE_MODE_MAX_VALUE + 1);

    static const char* strings_conversion_mode[] =
    {
        "NONE",
        "FLOAT16",
        "SINT8",
        "UINT8",
        "SINT16",
        "UINT16"
    };
    ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_conversion_mode) == ZYDIS_CONVERSION_MODE_MAX_VALUE + 1);

    PrintSectionHeader("AVX");

    PRINT_VALUE_B("VECTORLEN", "%03d", instruction->avx.vector_length);
    PRINT_VALUE_B("BROADCAST", "%s%s%s", strings_broadcast_mode[instruction->avx.broadcast.mode],
        CVT100_OUT(COLOR_VALUE_LABEL), instruction->avx.broadcast.is_static ? " (static)" : "");

    switch (instruction->encoding)
    {
    case ZYDIS_INSTRUCTION_ENCODING_EVEX:
        PRINT_VALUE_B("ROUNDING", "%s", strings_rounding_mode[instruction->avx.rounding.mode]);
        PRINT_VALUE_B("SAE", "%s", instruction->avx.has_sae ? "Y" : "N");
        PRINT_VALUE_R("MASK", "%s %s[%s%s%s]",
            ZydisRegisterGetString(instruction->avx.mask.reg),
            CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(COLOR_VALUE_B),
            strings_mask_mode[instruction->avx.mask.mode], CVT100_OUT(COLOR_VALUE_LABEL));
        break;
    case ZYDIS_INSTRUCTION_ENCODING_MVEX:
        PRINT_VALUE_B("ROUNDING", "%s", strings_rounding_mode[instruction->avx.rounding.mode]);
        PRINT_VALUE_B("SAE", "%s", instruction->avx.has_sae ? "Y" : "N");
        PRINT_VALUE_R("MASK", "%s %s[%sMERGING%s]",
            ZydisRegisterGetString(instruction->avx.mask.reg),
            CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(COLOR_VALUE_B),
            CVT100_OUT(COLOR_VALUE_LABEL));
        PRINT_VALUE_B("EH", "%s", instruction->avx.has_eviction_hint ? "Y" : "N");
        PRINT_VALUE_B("SWIZZLE", "%s", strings_swizzle_mode[instruction->avx.swizzle.mode]);
        PRINT_VALUE_B("CONVERT", "%s", strings_conversion_mode[instruction->avx.conversion.mode]);
        break;
    default:
        break;
    }
}

/**
 * Prints the formatted instruction disassembly.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 * @param   operands    A pointer to the first `ZydisDecodedOperand` struct of the instruction.
 * @param   style       The formatter style.
 */
static void PrintDisassembly(const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands, ZydisFormatterStyle style)
{
    ZyanStatus status;
    ZydisFormatter formatter;

    switch (style)
    {
    case ZYDIS_FORMATTER_STYLE_ATT:
        if (!ZYAN_SUCCESS(status = ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_ATT)))
        {
            PrintStatusError(status, "Failed to initialize instruction-formatter");
            exit(status);
        }
        PrintSectionHeader("ATT");
        break;
    case ZYDIS_FORMATTER_STYLE_INTEL:
        if (!ZYAN_SUCCESS(status = ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)) ||
            !ZYAN_SUCCESS(status = ZydisFormatterSetProperty(&formatter,
                ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE)) ||
            !ZYAN_SUCCESS(status = ZydisFormatterSetProperty(&formatter,
                ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE)))
        {
            PrintStatusError(status, "Failed to initialize instruction-formatter");
            exit(status);
        }
        PrintSectionHeader("INTEL");
        break;
    default:
        ZYAN_UNREACHABLE;
    }

    ZyanU8 buffer[256];
    const ZydisFormatterToken* token;

    PrintValueLabel("ABSOLUTE");
    if (!ZYAN_SUCCESS(status = ZydisFormatterTokenizeInstruction(&formatter, instruction, operands,
        instruction->operand_count_visible, buffer, sizeof(buffer), 0, &token, ZYAN_NULL)))
    {
        PrintStatusError(status, "Failed to tokenize instruction");
        exit(status);
    }
    PrintTokenizedInstruction(token);
    PrintValueLabel("RELATIVE");
    if (!ZYAN_SUCCESS(status = ZydisFormatterTokenizeInstruction(&formatter, instruction, operands,
        instruction->operand_count_visible, buffer, sizeof(buffer), ZYDIS_RUNTIME_ADDRESS_NONE,
        &token, ZYAN_NULL)))
    {
        PrintStatusError(status, "Failed to tokenize instruction");
        exit(status);
    }
    PrintTokenizedInstruction(token);
}

/**
 * Dumps basic instruction info.
 *
 * @param   decoder     A pointer to the `ZydisDecoder` instance.
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 * @param   operands    A pointer to the first `ZydisDecodedOperand` struct of the instruction.
 */
static void PrintInstruction(const ZydisDecoder* decoder,
    const ZydisDecodedInstruction* instruction, const ZydisDecodedOperand* operands)
{
    static const char* opcode_maps[] =
    {
        "DEFAULT",
        "0F",
        "0F38",
        "0F3A",
        "MAP4",
        "MAP5",
        "MAP6",
        "MAP7",
        "0F0F",
        "XOP8",
        "XOP9",
        "XOPA"
    };
    ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(opcode_maps) == ZYDIS_OPCODE_MAP_MAX_VALUE + 1);

    static const char* instr_encodings[] =
    {
        "DEFAULT",
        "3DNOW",
        "XOP",
        "VEX",
        "EVEX",
        "MVEX"
    };
    ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(instr_encodings) == ZYDIS_INSTRUCTION_ENCODING_MAX_VALUE + 1);

    static const char* exception_classes[] =
    {
        "NONE",
        "SSE1",
        "SSE2",
        "SSE3",
        "SSE4",
        "SSE5",
        "SSE7",
        "AVX1",
        "AVX2",
        "AVX3",
        "AVX4",
        "AVX5",
        "AVX6",
        "AVX7",
        "AVX8",
        "AVX11",
        "AVX12",
        "E1",
        "E1NF",
        "E2",
        "E2NF",
        "E3",
        "E3NF",
        "E4",
        "E4NF",
        "E5",
        "E5NF",
        "E6",
        "E6NF",
        "E7NM",
        "E7NM128",
        "E9NF",
        "E10",
        "E10NF",
        "E11",
        "E11NF",
        "E12",
        "E12NP",
        "K20",
        "K21",
        "AMXE1",
        "AMXE2",
        "AMXE3",
        "AMXE4",
        "AMXE5",
        "AMXE6"
    };
    ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(exception_classes) == ZYDIS_EXCEPTION_CLASS_MAX_VALUE + 1);

    static const struct
    {
        ZydisInstructionAttributes attribute_mask;
        const char* str;
    } attribute_map[] =
    {
        { ZYDIS_ATTRIB_HAS_MODRM,                "HAS_MODRM"                },
        { ZYDIS_ATTRIB_HAS_SIB,                  "HAS_SIB"                  },
        { ZYDIS_ATTRIB_HAS_REX,                  "HAS_REX"                  },
        { ZYDIS_ATTRIB_HAS_XOP,                  "HAS_XOP"                  },
        { ZYDIS_ATTRIB_HAS_VEX,                  "HAS_VEX"                  },
        { ZYDIS_ATTRIB_HAS_EVEX,                 "HAS_EVEX"                 },
        { ZYDIS_ATTRIB_HAS_MVEX,                 "HAS_MVEX"                 },
        { ZYDIS_ATTRIB_IS_RELATIVE,              "IS_RELATIVE"              },
        { ZYDIS_ATTRIB_IS_PRIVILEGED,            "IS_PRIVILEGED"            },
        { ZYDIS_ATTRIB_CPUFLAG_ACCESS,           "CPUFLAG_ACCESS"           },
        { ZYDIS_ATTRIB_CPU_STATE_CR,             "CPU_STATE_CR"             },
        { ZYDIS_ATTRIB_CPU_STATE_CW,             "CPU_STATE_CW"             },
        { ZYDIS_ATTRIB_FPU_STATE_CR,             "FPU_STATE_CR"             },
        { ZYDIS_ATTRIB_FPU_STATE_CW,             "FPU_STATE_CW"             },
        { ZYDIS_ATTRIB_XMM_STATE_CR,             "XMM_STATE_CR"             },
        { ZYDIS_ATTRIB_XMM_STATE_CW,             "XMM_STATE_CW"             },
        { ZYDIS_ATTRIB_ACCEPTS_LOCK,             "ACCEPTS_LOCK"             },
        { ZYDIS_ATTRIB_ACCEPTS_REP,              "ACCEPTS_REP"              },
        { ZYDIS_ATTRIB_ACCEPTS_REPE,             "ACCEPTS_REPE"             },
        { ZYDIS_ATTRIB_ACCEPTS_REPZ,             "ACCEPTS_REPZ"             },
        { ZYDIS_ATTRIB_ACCEPTS_REPNE,            "ACCEPTS_REPNE"            },
        { ZYDIS_ATTRIB_ACCEPTS_REPNZ,            "ACCEPTS_REPNZ"            },
        { ZYDIS_ATTRIB_ACCEPTS_BND,              "ACCEPTS_BND"              },
        { ZYDIS_ATTRIB_ACCEPTS_XACQUIRE,         "ACCEPTS_XACQUIRE"         },
        { ZYDIS_ATTRIB_ACCEPTS_XRELEASE,         "ACCEPTS_XRELEASE"         },
        { ZYDIS_ATTRIB_ACCEPTS_HLE_WITHOUT_LOCK, "ACCEPTS_HLE_WITHOUT_LOCK" },
        { ZYDIS_ATTRIB_ACCEPTS_BRANCH_HINTS,     "ACCEPTS_BRANCH_HINTS"     },
        { ZYDIS_ATTRIB_ACCEPTS_SEGMENT,          "ACCEPTS_SEGMENT"          },
        { ZYDIS_ATTRIB_HAS_LOCK,                 "HAS_LOCK"                 },
        { ZYDIS_ATTRIB_HAS_REP,                  "HAS_REP"                  },
        { ZYDIS_ATTRIB_HAS_REPE,                 "HAS_REPE"                 },
        { ZYDIS_ATTRIB_HAS_REPZ,                 "HAS_REPZ"                 },
        { ZYDIS_ATTRIB_HAS_REPNE,                "HAS_REPNE"                },
        { ZYDIS_ATTRIB_HAS_REPNZ,                "HAS_REPNZ"                },
        { ZYDIS_ATTRIB_HAS_BND,                  "HAS_BND"                  },
        { ZYDIS_ATTRIB_HAS_XACQUIRE,             "HAS_XACQUIRE"             },
        { ZYDIS_ATTRIB_HAS_XRELEASE,             "HAS_XRELEASE"             },
        { ZYDIS_ATTRIB_HAS_BRANCH_NOT_TAKEN,     "HAS_BRANCH_NOT_TAKEN"     },
        { ZYDIS_ATTRIB_HAS_BRANCH_TAKEN,         "HAS_BRANCH_TAKEN"         },
        { ZYDIS_ATTRIB_HAS_SEGMENT,              "HAS_SEGMENT"              },
        { ZYDIS_ATTRIB_HAS_SEGMENT_CS,           "HAS_SEGMENT_CS"           },
        { ZYDIS_ATTRIB_HAS_SEGMENT_SS,           "HAS_SEGMENT_SS"           },
        { ZYDIS_ATTRIB_HAS_SEGMENT_DS,           "HAS_SEGMENT_DS"           },
        { ZYDIS_ATTRIB_HAS_SEGMENT_ES,           "HAS_SEGMENT_ES"           },
        { ZYDIS_ATTRIB_HAS_SEGMENT_FS,           "HAS_SEGMENT_FS"           },
        { ZYDIS_ATTRIB_HAS_SEGMENT_GS,           "HAS_SEGMENT_GS"           },
        { ZYDIS_ATTRIB_HAS_OPERANDSIZE,          "HAS_OPERANDSIZE"          },
        { ZYDIS_ATTRIB_HAS_ADDRESSSIZE,          "HAS_ADDRESSSIZE"          },
        { ZYDIS_ATTRIB_ACCEPTS_NOTRACK,          "ACCEPTS_NOTRACK"          },
        { ZYDIS_ATTRIB_HAS_NOTRACK,              "HAS_NOTRACK"              }
    };

    PrintSectionHeader("BASIC");
    PrintValueLabel("MNEMONIC");
    ZYAN_PRINTF("%s%s%s [ENC: %s%s%s, MAP: %s%s%s, OPC: %s0x%02X%s]%s\n",
        CVT100_OUT(COLOR_VALUE_R), ZydisMnemonicGetString(instruction->mnemonic),
        CVT100_OUT(COLOR_VALUE_LABEL),
        CVT100_OUT(COLOR_VALUE_B), instr_encodings[instruction->encoding],
        CVT100_OUT(COLOR_VALUE_LABEL),
        CVT100_OUT(COLOR_VALUE_B), opcode_maps[instruction->opcode_map],
        CVT100_OUT(COLOR_VALUE_LABEL),
        CVT100_OUT(COLOR_VALUE_G), instruction->opcode,
        CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(COLOR_DEFAULT));
    PRINT_VALUE_G("LENGTH"    , "%2d", instruction->length);
    PRINT_VALUE_G("SSZ"       , "%2d", instruction->stack_width);
    PRINT_VALUE_G("EOSZ"      , "%2d", instruction->operand_width);
    PRINT_VALUE_G("EASZ"      , "%2d", instruction->address_width);
    PRINT_VALUE_B("CATEGORY"  , "%s" , ZydisCategoryGetString(instruction->meta.category));
    PRINT_VALUE_B("ISA-SET"   , "%s" , ZydisISASetGetString(instruction->meta.isa_set));
    PRINT_VALUE_B("ISA-EXT"   , "%s" , ZydisISAExtGetString(instruction->meta.isa_ext));
    PRINT_VALUE_B("EXCEPTIONS", "%s" , exception_classes[instruction->meta.exception_class]);

    if (instruction->attributes)
    {
        PrintValueLabel("ATTRIBUTES");
        ZYAN_FPUTS(CVT100_OUT(COLOR_VALUE_B), ZYAN_STDOUT);
        ZyanUSize len_total = 13;
        for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(attribute_map); ++i)
        {
            if (instruction->attributes & attribute_map[i].attribute_mask)
            {
                const ZyanUSize len = ZYAN_STRLEN(attribute_map[i].str);
                if (len_total + len > 109)
                {
                    len_total = 13;
                    ZYAN_PRINTF("\n             ");
                }
                len_total += ZYAN_PRINTF("%s ", attribute_map[i].str);
            }
        }
        ZYAN_PUTS(CVT100_OUT(COLOR_DEFAULT));
    }

#if !defined(ZYDIS_DISABLE_ENCODER)

    PrintValueLabel("OPTIMIZED");
    PrintSizeOptimizedForm(decoder, instruction, operands, instruction->operand_count_visible);

#else
    ZYAN_UNUSED(decoder);
#endif

    if (instruction->operand_count > 0)
    {
        ZYAN_PUTS("");
        PrintOperands(instruction, operands);
    }

    if (instruction->attributes & ZYDIS_ATTRIB_CPUFLAG_ACCESS)
    {
        ZYAN_PUTS("");
        PrintFlags(instruction);
    }

    if ((instruction->encoding == ZYDIS_INSTRUCTION_ENCODING_XOP) ||
        (instruction->encoding == ZYDIS_INSTRUCTION_ENCODING_VEX) ||
        (instruction->encoding == ZYDIS_INSTRUCTION_ENCODING_EVEX) ||
        (instruction->encoding == ZYDIS_INSTRUCTION_ENCODING_MVEX))
    {
        ZYAN_PUTS("");
        PrintAVXInfo(instruction);
    }

    ZYAN_PUTS("");
    PrintDisassembly(instruction, operands, ZYDIS_FORMATTER_STYLE_ATT);
    ZYAN_PUTS("");
    PrintDisassembly(instruction, operands, ZYDIS_FORMATTER_STYLE_INTEL);
}

/* ============================================================================================== */
/* Entry point                                                                                    */
/* ============================================================================================== */

void PrintUsage(int argc, char* argv[])
{
    ZYAN_FPRINTF(ZYAN_STDERR, "%sUsage: %s <machine_mode> [stack_width] <hexbytes>\n\n"
        "Machine mode:      -real|-16|-32|-64\n"
        "Stack width:       -16|-32|-64%s\n",
        CVT100_ERR(COLOR_ERROR), (argc > 0 ? argv[0] : "ZydisInfo"),
        CVT100_ERR(ZYAN_VT100SGR_RESET));
}

int main(int argc, char** argv)
{
    InitVT100();

    if (ZydisGetVersion() != ZYDIS_VERSION)
    {
        ZYAN_FPRINTF(ZYAN_STDERR, "%sInvalid zydis version%s\n",
            CVT100_ERR(COLOR_ERROR), CVT100_ERR(ZYAN_VT100SGR_RESET));
        return ZYAN_STATUS_INVALID_OPERATION;
    }

    if (argc < 3)
    {
        PrintUsage(argc, argv);
        return ZYAN_STATUS_INVALID_ARGUMENT;
    }

    ZydisDecoder decoder;
    ZydisMachineMode machine_mode;
    ZydisStackWidth stack_width;
    ZyanU8 hexbytes_index = 2;
    if (!ZYAN_STRCMP(argv[1], "-real"))
    {
        machine_mode = ZYDIS_MACHINE_MODE_REAL_16;
        stack_width = ZYDIS_STACK_WIDTH_16;
    }
    else if (!ZYAN_STRCMP(argv[1], "-16"))
    {
        machine_mode = ZYDIS_MACHINE_MODE_LONG_COMPAT_16;
        stack_width = ZYDIS_STACK_WIDTH_16;
    }
    else if (!ZYAN_STRCMP(argv[1], "-32"))
    {
        machine_mode = ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
        stack_width = ZYDIS_STACK_WIDTH_32;
    }
    else if (!ZYAN_STRCMP(argv[1], "-64"))
    {
        machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        stack_width = ZYDIS_STACK_WIDTH_64;
    }
    else
    {
        PrintUsage(argc, argv);
        return ZYAN_STATUS_INVALID_ARGUMENT;
    }
    if ((argc > 3) && (argv[2][0] == '-'))
    {
        ++hexbytes_index;
        if (!ZYAN_STRCMP(argv[2], "-16"))
        {
            stack_width = ZYDIS_STACK_WIDTH_16;
        }
        else if (!ZYAN_STRCMP(argv[2], "-32"))
        {
            stack_width = ZYDIS_STACK_WIDTH_32;
        }
        else if (!ZYAN_STRCMP(argv[2], "-64"))
        {
            stack_width = ZYDIS_STACK_WIDTH_64;
        }
        else
        {
            PrintUsage(argc, argv);
            return ZYAN_STATUS_INVALID_ARGUMENT;
        }
    }
    ZyanStatus status = ZydisDecoderInit(&decoder, machine_mode, stack_width);
    if (!ZYAN_SUCCESS(status))
    {
        PrintStatusError(status, "Failed to initialize decoder");
        return status;
    }

    ZyanU8 data[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanU8 byte_length = 0;
    for (ZyanU8 i = hexbytes_index; i < argc; ++i)
    {
        char* cur_arg = argv[i];

        // Strip whitespace in-place.
        const ZyanUSize arg_len = ZYAN_STRLEN(cur_arg);
        ZyanUSize write = 0;
        for (ZyanUSize read = 0; read < arg_len; ++read)
        {
            char ch = cur_arg[read];
            if (ch == ' ' || ch == '\t') continue;
            cur_arg[write++] = ch;
        }
        cur_arg[write] = '\0';

        if (write % 2)
        {
            ZYAN_FPRINTF(ZYAN_STDERR, "%sEven number of hex nibbles expected%s\n",
                CVT100_ERR(COLOR_ERROR), CVT100_ERR(ZYAN_VT100SGR_RESET));
            return ZYAN_STATUS_INVALID_ARGUMENT;
        }
        if ((write / 2) + byte_length > ZYDIS_MAX_INSTRUCTION_LENGTH)
        {
            ZYAN_FPRINTF(ZYAN_STDERR, "%sMaximum number of %d bytes exceeded%s\n",
                CVT100_ERR(COLOR_ERROR), ZYDIS_MAX_INSTRUCTION_LENGTH,
                CVT100_ERR(ZYAN_VT100SGR_RESET));
            return ZYAN_STATUS_INVALID_ARGUMENT;
        }
        for (ZyanU8 j = 0; j < write / 2; ++j)
        {
            unsigned value;
            if (!ZYAN_SSCANF(&cur_arg[j * 2], "%02x", &value))
            {
                ZYAN_FPRINTF(ZYAN_STDERR, "%sInvalid hex value%s\n",
                    CVT100_ERR(COLOR_ERROR), CVT100_ERR(ZYAN_VT100SGR_RESET));
                return ZYAN_STATUS_INVALID_ARGUMENT;
            }
            data[byte_length] = (ZyanU8)value;
            ++byte_length;
        }
    }

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    status = ZydisDecoderDecodeFull(&decoder, &data, byte_length, &instruction, operands);
    if (!ZYAN_SUCCESS(status))
    {
        PrintStatusError(status, "Could not decode instruction");
        return status;
    }

    PrintInstruction(&decoder, &instruction, operands);

#if !defined(ZYDIS_DISABLE_SEGMENT)
    ZYAN_PUTS("");
    PrintSectionHeader("SEGMENTS");
    PrintSegments(&instruction, &data[0], ZYAN_TRUE);
#endif

    return EXIT_SUCCESS;
}

/* ============================================================================================== */
