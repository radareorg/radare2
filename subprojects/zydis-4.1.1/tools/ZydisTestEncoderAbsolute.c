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
 * Test set for `ZydisEncoderEncodeInstructionAbsolute`.
 */

#include <inttypes.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>
#include <Zydis/Internal/EncoderData.h>

/* ============================================================================================== */
/* Enums and Types                                                                                */
/* ============================================================================================== */

#define TEST_RUNTIME_ADDRESS 0x00004000ULL

typedef struct Iterator_
{
    ZyanU32 value;
    ZyanU32 limit;
} Iterator;

typedef struct DecodedInstruction_
{
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
} DecodedInstruction;

/* ============================================================================================== */
/* Helper functions                                                                               */
/* ============================================================================================== */

static ZyanBool AdvanceIterators(Iterator *iterators, ZyanUSize count)
{
    if (!iterators || !count)
    {
        return ZYAN_FALSE;
    }

    for (ZyanUSize i = 0; i < count; ++i)
    {
        Iterator *iterator = &iterators[count - 1 - i];
        iterator->value++;
        if (iterator->value < iterator->limit)
        {
            return ZYAN_TRUE;
        }
        iterator->value = 0;
    }

    return ZYAN_FALSE;
}

static void PrintBytes(ZyanU8 *bytes, ZyanUSize count)
{
    for (ZyanUSize i = 0; i < count; ++i)
    {
        ZYAN_PRINTF("%02X ", bytes[i]);
    }
}

static ZyanI8 GetRelativeOperandIndex(const ZydisEncoderRequest *req)
{
    for (ZyanU8 i = 0; i < req->operand_count; ++i)
    {
        const ZyanBool is_rip_rel = (req->operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) &&
            ((req->operands[i].mem.base == ZYDIS_REGISTER_EIP) ||
             (req->operands[i].mem.base == ZYDIS_REGISTER_RIP));
        if (is_rip_rel || (req->operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE))
        {
            return (ZyanI8)i;
        }
    }
    return -1;
}

static ZyanBool Disassemble(DecodedInstruction *decoded, ZyanU8 *bytes, ZyanUSize size,
    ZydisMachineMode machine_mode)
{
    ZydisDecoder decoder;
    ZydisStackWidth stack_width;
    switch (machine_mode)
    {
    case ZYDIS_MACHINE_MODE_LONG_COMPAT_16:
        stack_width = ZYDIS_STACK_WIDTH_16;
        break;
    case ZYDIS_MACHINE_MODE_LONG_COMPAT_32:
        stack_width = ZYDIS_STACK_WIDTH_32;
        break;
    case ZYDIS_MACHINE_MODE_LONG_64:
        stack_width = ZYDIS_STACK_WIDTH_64;
        break;
    default:
        ZYAN_UNREACHABLE;
    }
    if (ZYAN_FAILED(ZydisDecoderInit(&decoder, machine_mode, stack_width)))
    {
        return ZYAN_FALSE;
    }
    if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder, bytes, size, &decoded->insn,
        decoded->operands)))
    {
        return ZYAN_FALSE;
    }
    return ZYAN_TRUE;
}

/* ============================================================================================== */
/* Tests                                                                                          */
/* ============================================================================================== */

static ZyanBool RunTest(ZydisEncoderRequest *req, const char *test_name, ZyanBool is_rip_rel_test)
{
    ZyanU8 instruction1[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize length1 = sizeof(instruction1);
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(req, instruction1, &length1)))
    {
        ZYAN_PRINTF("%s: NOT ENCODABLE\n", test_name);
        return ZYAN_TRUE;
    }
    ZyanI8 rel_op_index = GetRelativeOperandIndex(req);
    if (rel_op_index < 0)
    {
        ZYAN_PRINTF("%s: NO RELATIVE OPERAND FOUND\n", test_name);
        return ZYAN_FALSE;
    }
    DecodedInstruction decoded;
    if (!Disassemble(&decoded, instruction1, length1, req->machine_mode))
    {
        ZYAN_PRINTF("%s: FAILED TO DISASSEMBLE\n", test_name);
        return ZYAN_FALSE;
    }
    ZyanU64 absolute_address = 0;
    if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&decoded.insn, &decoded.operands[rel_op_index],
        TEST_RUNTIME_ADDRESS, &absolute_address)))
    {
        ZYAN_PRINTF("%s: FAILED TO COMPUTE ABSOLUTE ADDRESS\n", test_name);
        return ZYAN_FALSE;
    }
    if (is_rip_rel_test)
    {
        ZYAN_ASSERT(req->operands[rel_op_index].type == ZYDIS_OPERAND_TYPE_MEMORY);
        req->operands[rel_op_index].mem.displacement = absolute_address;
    }
    else
    {
        ZYAN_ASSERT(req->operands[rel_op_index].type == ZYDIS_OPERAND_TYPE_IMMEDIATE);
        req->operands[rel_op_index].imm.u = absolute_address;
    }

    ZyanU8 instruction2[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize length2 = sizeof(instruction2);
    if (ZYAN_FAILED(ZydisEncoderEncodeInstructionAbsolute(req, instruction2, &length2,
        TEST_RUNTIME_ADDRESS)))
    {
        ZYAN_PRINTF("%s: FAILED TO ENCODE INSTRUCTION\n", test_name);
        return ZYAN_FALSE;
    }
    ZYAN_PRINTF("%s: ", test_name);
    PrintBytes(instruction1, length1);
    if ((length1 != length2) || ZYAN_MEMCMP(instruction1, instruction2, length1))
    {
        ZYAN_PRINTF("!= ");
        PrintBytes(instruction2, length2);
        ZYAN_PRINTF("\n");
        return ZYAN_FALSE;
    }
    ZYAN_PRINTF("\n");
    return ZYAN_TRUE;
}

static ZyanBool RunTestAbsolute(ZydisEncoderRequest *req, const char *test_name,
    ZyanU64 runtime_address)
{
    ZyanI8 rel_op_index = GetRelativeOperandIndex(req);
    if (rel_op_index < 0)
    {
        ZYAN_PRINTF("%s: NO RELATIVE OPERAND FOUND\n", test_name);
        return ZYAN_FALSE;
    }
    ZyanU64 desired_address;
    const ZydisEncoderOperand *rel_op = &req->operands[rel_op_index];
    if (rel_op->type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
    {
        desired_address = rel_op->imm.u;
    }
    else if (rel_op->type == ZYDIS_OPERAND_TYPE_MEMORY)
    {
        desired_address = rel_op->mem.displacement;
    }
    else
    {
        return ZYAN_FALSE;
    }
    ZyanU8 instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize length = sizeof(instruction);
    if (ZYAN_FAILED(ZydisEncoderEncodeInstructionAbsolute(req, instruction, &length,
        runtime_address)))
    {
        ZYAN_PRINTF("%s: FAILED TO ENCODE INSTRUCTION\n", test_name);
        return ZYAN_FALSE;
    }
    DecodedInstruction decoded;
    if (!Disassemble(&decoded, instruction, length, req->machine_mode))
    {
        ZYAN_PRINTF("%s: FAILED TO DISASSEMBLE\n", test_name);
        return ZYAN_FALSE;
    }
    ZyanU64 absolute_address = 0;
    if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&decoded.insn, &decoded.operands[rel_op_index],
        runtime_address, &absolute_address)))
    {
        ZYAN_PRINTF("%s: FAILED TO COMPUTE ABSOLUTE ADDRESS\n", test_name);
        return ZYAN_FALSE;
    }
    if (absolute_address != desired_address)
    {
        ZYAN_PRINTF("%s: %016" PRIX64 " != %016" PRIX64 "\n", test_name, absolute_address,
            desired_address);
        return ZYAN_FALSE;
    }
    return ZYAN_TRUE;
}

static ZyanBool RunBranchingTests(void)
{
    static const ZydisMnemonic instructions[] =
    {
        ZYDIS_MNEMONIC_CALL,
        ZYDIS_MNEMONIC_JZ,
        ZYDIS_MNEMONIC_JCXZ,
        ZYDIS_MNEMONIC_JECXZ,
        ZYDIS_MNEMONIC_JRCXZ,
        ZYDIS_MNEMONIC_JKZD,
        ZYDIS_MNEMONIC_JMP,
    };
    static const ZydisMachineMode modes[] =
    {
        ZYDIS_MACHINE_MODE_LONG_COMPAT_16,
        ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        ZYDIS_MACHINE_MODE_LONG_64,
    };
    static const char *str_modes[] =
    {
        "M16",
        "M32",
        "M64",
    };
    static const ZyanU64 rels[] =
    {
        0x11,
        0x2222,
        0x44444444,
    };
    static const ZydisBranchType branch_types[] =
    {
        ZYDIS_BRANCH_TYPE_NONE,
        ZYDIS_BRANCH_TYPE_SHORT,
        ZYDIS_BRANCH_TYPE_NEAR,
    };
    static const char *str_branch_types[] =
    {
        "T0",
        "TS",
        "TN",
    };
    static const ZydisBranchWidth branch_widths[] =
    {
        ZYDIS_BRANCH_WIDTH_NONE,
        ZYDIS_BRANCH_WIDTH_8,
        ZYDIS_BRANCH_WIDTH_16,
        ZYDIS_BRANCH_WIDTH_32,
        ZYDIS_BRANCH_WIDTH_64,
    };
    static const char *str_branch_widths[] =
    {
        "W00",
        "W08",
        "W16",
        "W32",
        "W64",
    };
    static const ZydisInstructionAttributes prefixes[] = {
        0,
        ZYDIS_ATTRIB_HAS_BRANCH_TAKEN,
        ZYDIS_ATTRIB_HAS_BND,
        ZYDIS_ATTRIB_HAS_BRANCH_NOT_TAKEN | ZYDIS_ATTRIB_HAS_BND,
    };
    static const char *str_prefixes[] =
    {
        "P00",
        "PBT",
        "PBD",
        "PBN+PBD",
    };
    static const ZydisAddressSizeHint address_hints[] =
    {
        ZYDIS_ADDRESS_SIZE_HINT_NONE,
        ZYDIS_ADDRESS_SIZE_HINT_16,
        ZYDIS_ADDRESS_SIZE_HINT_32,
        ZYDIS_ADDRESS_SIZE_HINT_64,
    };
    static const char *str_address_hints[] =
    {
        "AH00",
        "AH16",
        "AH32",
        "AH64",
    };
    static const ZydisOperandSizeHint operand_hints[] =
    {
        ZYDIS_OPERAND_SIZE_HINT_NONE,
        ZYDIS_OPERAND_SIZE_HINT_8,
        ZYDIS_OPERAND_SIZE_HINT_16,
        ZYDIS_OPERAND_SIZE_HINT_32,
        ZYDIS_OPERAND_SIZE_HINT_64,
    };
    static const char *str_operand_hints[] =
    {
        "OH00",
        "OH08",
        "OH16",
        "OH32",
        "OH64",
    };

    ZydisEncoderRequest req;
    ZyanBool all_passed = ZYAN_TRUE;
    Iterator iter_branches[6] =
    {
        { 0, ZYAN_ARRAY_LENGTH(instructions) },
        { 0, ZYAN_ARRAY_LENGTH(modes) },
        { 0, ZYAN_ARRAY_LENGTH(rels) },
        { 0, ZYAN_ARRAY_LENGTH(branch_types) },
        { 0, ZYAN_ARRAY_LENGTH(branch_widths) },
        { 0, ZYAN_ARRAY_LENGTH(prefixes) },
    };
    do
    {
        ZydisMnemonic mnemonic = instructions[iter_branches[0].value];
        ZydisMachineMode mode = modes[iter_branches[1].value];
        ZyanU64 rel = rels[iter_branches[2].value];
        ZydisBranchType branch_type = branch_types[iter_branches[3].value];
        ZydisBranchWidth branch_width = branch_widths[iter_branches[4].value];
        ZydisInstructionAttributes prefix = prefixes[iter_branches[5].value];

        const ZydisEncoderRelInfo *rel_info = ZydisGetRelInfo(mnemonic);
        ZYAN_ASSERT(rel_info);
        if ((!rel_info->accepts_branch_hints) && (prefix & (ZYDIS_ATTRIB_HAS_BRANCH_TAKEN |
                                                            ZYDIS_ATTRIB_HAS_BRANCH_NOT_TAKEN)))
        {
            continue;
        }
        if ((!rel_info->accepts_bound) && (prefix & ZYDIS_ATTRIB_HAS_BND))
        {
            continue;
        }

        ZYAN_MEMSET(&req, 0, sizeof(req));
        req.machine_mode = mode;
        req.mnemonic = mnemonic;
        req.prefixes = prefix;
        req.branch_type = branch_type;
        req.branch_width = branch_width;
        if (mnemonic != ZYDIS_MNEMONIC_JKZD)
        {
            req.operand_count = 1;
            req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
            req.operands[0].imm.u = rel;
        }
        else
        {
            req.operand_count = 2;
            req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
            req.operands[0].reg.value = ZYDIS_REGISTER_K1;
            req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
            req.operands[1].imm.u = rel;
        }

        char test_name[256];
        snprintf(test_name, sizeof(test_name), "%s:%s:%08" PRIX64 ":%s:%s:%s",
            ZydisMnemonicGetString(mnemonic),
            str_modes[iter_branches[1].value],
            rel,
            str_branch_types[iter_branches[3].value],
            str_branch_widths[iter_branches[4].value],
            str_prefixes[iter_branches[5].value]);
        all_passed &= RunTest(&req, test_name, ZYAN_FALSE);
    } while (AdvanceIterators(iter_branches, ZYAN_ARRAY_LENGTH(iter_branches)));

    Iterator iter_asz_branches[4] =
    {
        { 0, ZYAN_ARRAY_LENGTH(modes) },
        { 0, ZYAN_ARRAY_LENGTH(branch_types) },
        { 0, ZYAN_ARRAY_LENGTH(branch_widths) },
        { 0, ZYAN_ARRAY_LENGTH(address_hints) },
    };
    do
    {
        ZydisMachineMode mode = modes[iter_asz_branches[0].value];
        ZydisBranchType branch_type = branch_types[iter_asz_branches[1].value];
        ZydisBranchWidth branch_width = branch_widths[iter_asz_branches[2].value];
        ZydisAddressSizeHint address_hint = address_hints[iter_asz_branches[3].value];

        ZYAN_MEMSET(&req, 0, sizeof(req));
        req.machine_mode = mode;
        req.mnemonic = ZYDIS_MNEMONIC_LOOP;
        req.branch_type = branch_type;
        req.branch_width = branch_width;
        req.address_size_hint = address_hint;
        req.operand_count = 1;
        req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        req.operands[0].imm.u = 0x55;

        char test_name[256];
        snprintf(test_name, sizeof(test_name), "%s:%s:%s:%s:%s",
            ZydisMnemonicGetString(req.mnemonic),
            str_modes[iter_asz_branches[0].value],
            str_branch_types[iter_asz_branches[1].value],
            str_branch_widths[iter_asz_branches[2].value],
            str_address_hints[iter_asz_branches[3].value]);
        all_passed &= RunTest(&req, test_name, ZYAN_FALSE);
    } while (AdvanceIterators(iter_asz_branches, ZYAN_ARRAY_LENGTH(iter_asz_branches)));

    Iterator iter_osz_branches[3] =
    {
        { 0, ZYAN_ARRAY_LENGTH(modes) },
        { 0, ZYAN_ARRAY_LENGTH(rels) },
        { 0, ZYAN_ARRAY_LENGTH(operand_hints) },
    };
    do
    {
        ZydisMachineMode mode = modes[iter_osz_branches[0].value];
        ZyanU64 rel = rels[iter_osz_branches[1].value];
        ZydisOperandSizeHint operand_hint = operand_hints[iter_osz_branches[2].value];

        ZYAN_MEMSET(&req, 0, sizeof(req));
        req.machine_mode = mode;
        req.mnemonic = ZYDIS_MNEMONIC_XBEGIN;
        req.operand_size_hint = operand_hint;
        req.operand_count = 1;
        req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        req.operands[0].imm.u = rel;

        char test_name[256];
        snprintf(test_name, sizeof(test_name), "%s:%s:%08" PRIX64 ":%s",
            ZydisMnemonicGetString(req.mnemonic),
            str_modes[iter_osz_branches[0].value],
            rel,
            str_operand_hints[iter_osz_branches[2].value]);
        all_passed &= RunTest(&req, test_name, ZYAN_FALSE);
    } while (AdvanceIterators(iter_osz_branches, ZYAN_ARRAY_LENGTH(iter_osz_branches)));

    return all_passed;
}

static ZyanBool RunRipRelativeTests(void)
{
    ZydisEncoderRequest req;
    ZyanBool all_passed = ZYAN_TRUE;

    // Basic test
    ZYAN_MEMSET(&req, 0, sizeof(req));
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    req.mnemonic = ZYDIS_MNEMONIC_XOR;
    req.operand_count = 2;
    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
    req.operands[0].reg.value = ZYDIS_REGISTER_RAX;
    req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
    req.operands[1].mem.base = ZYDIS_REGISTER_RIP;
    req.operands[1].mem.displacement = 0x66666666;
    req.operands[1].mem.size = 8;
    all_passed &= RunTest(&req, ZydisMnemonicGetString(req.mnemonic), ZYAN_TRUE);

    // Displacement + immediate
    ZYAN_MEMSET(&req, 0, sizeof(req));
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    req.mnemonic = ZYDIS_MNEMONIC_CMP;
    req.operand_count = 2;
    req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
    req.operands[0].mem.base = ZYDIS_REGISTER_RIP;
    req.operands[0].mem.displacement = 0x66666666;
    req.operands[0].mem.size = 4;
    req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    req.operands[1].imm.u = 0x11223344;
    all_passed &= RunTest(&req, ZydisMnemonicGetString(req.mnemonic), ZYAN_TRUE);

    // EIP-relative
    ZYAN_MEMSET(&req, 0, sizeof(req));
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    req.mnemonic = ZYDIS_MNEMONIC_SUB;
    req.operand_count = 2;
    req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
    req.operands[0].mem.base = ZYDIS_REGISTER_EIP;
    req.operands[0].mem.displacement = 0x66666666;
    req.operands[0].mem.size = 4;
    req.operands[1].type = ZYDIS_OPERAND_TYPE_REGISTER;
    req.operands[1].reg.value = ZYDIS_REGISTER_EBX;
    all_passed &= RunTest(&req, ZydisMnemonicGetString(req.mnemonic), ZYAN_TRUE);

    // AMD 3DNow!
    ZYAN_MEMSET(&req, 0, sizeof(req));
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    req.mnemonic = ZYDIS_MNEMONIC_PI2FD;
    req.operand_count = 2;
    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
    req.operands[0].reg.value = ZYDIS_REGISTER_MM1;
    req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
    req.operands[1].mem.base = ZYDIS_REGISTER_RIP;
    req.operands[1].mem.displacement = 0x66666666;
    req.operands[1].mem.size = 8;
    all_passed &= RunTest(&req, ZydisMnemonicGetString(req.mnemonic), ZYAN_TRUE);

    return all_passed;
}

static ZyanBool RunRangeTests(void)
{
    static const ZydisMnemonic instructions[] =
    {
        ZYDIS_MNEMONIC_CALL,
        ZYDIS_MNEMONIC_JZ,
        ZYDIS_MNEMONIC_JKZD,
        ZYDIS_MNEMONIC_JMP,
        ZYDIS_MNEMONIC_XBEGIN,
    };
    static const ZydisMachineMode modes[] =
    {
        ZYDIS_MACHINE_MODE_LONG_COMPAT_16,
        ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        ZYDIS_MACHINE_MODE_LONG_64,
    };
    static const ZyanU8 mode_widths[] =
    {
        16,
        32,
        64,
    };
    static const ZyanU64 offsets[] =
    {
        0x80,
        0x8000,
    };

    ZydisEncoderRequest req;
    ZyanBool all_passed = ZYAN_TRUE;
    Iterator iterators[3] =
    {
        { 0, ZYAN_ARRAY_LENGTH(instructions) },
        { 0, ZYAN_ARRAY_LENGTH(modes) },
        { 0, ZYAN_ARRAY_LENGTH(offsets) },
    };
    do
    {
        ZydisMnemonic mnemonic = instructions[iterators[0].value];
        ZydisMachineMode mode = modes[iterators[1].value];
        ZyanU64 offset = offsets[iterators[2].value];
        const ZydisEncoderRelInfo *rel_info = ZydisGetRelInfo(mnemonic);
        static const ZyanU8 empty_row[3] = { 0, 0, 0 };
        if (!memcmp(rel_info->size[iterators[1].value], empty_row, sizeof(empty_row)))
        {
            continue;
        }
        for (int i = 0; i < 8; ++i)
        {
            ZyanU64 target_address = TEST_RUNTIME_ADDRESS + offset + i;
            ZYAN_MEMSET(&req, 0, sizeof(req));
            req.machine_mode = mode;
            req.mnemonic = mnemonic;
            if (mnemonic != ZYDIS_MNEMONIC_JKZD)
            {
                req.operand_count = 1;
                req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                req.operands[0].imm.u = target_address;
            }
            else
            {
                req.operand_count = 2;
                req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
                req.operands[0].reg.value = ZYDIS_REGISTER_K1;
                req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                req.operands[1].imm.u = target_address;
            }
            char test_name[256];
            snprintf(test_name, sizeof(test_name), "M%02u:%016" PRIX64 ":%s",
                mode_widths[mode],
                target_address,
                ZydisMnemonicGetString(mnemonic));
            all_passed &= RunTestAbsolute(&req, test_name, TEST_RUNTIME_ADDRESS);
        }
    } while (AdvanceIterators(iterators, ZYAN_ARRAY_LENGTH(iterators)));

    if (all_passed)
    {
        ZYAN_PRINTF("All range tests passed\n");
    }
    return all_passed;
}

/* ============================================================================================== */
/* Entry point                                                                                    */
/* ============================================================================================== */

int main(void)
{
    ZyanBool all_passed = ZYAN_TRUE;
    ZYAN_PRINTF("Branching tests:\n");
    all_passed &= RunBranchingTests();
    ZYAN_PRINTF("\nEIP/RIP-relative tests:\n");
    all_passed &= RunRipRelativeTests();
    ZYAN_PRINTF("\nRange tests:\n");
    all_passed &= RunRangeTests();
    ZYAN_PRINTF("\n");
    if (!all_passed)
    {
        ZYAN_PRINTF("SOME TESTS FAILED\n");
        return 1;
    }

    ZYAN_PRINTF("ALL TESTS PASSED\n");
    return 0;
}

/* ============================================================================================== */
