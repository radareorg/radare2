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
 * This file implements fuzz target for encoder.
 */

#include "ZydisFuzzShared.h"

/* ============================================================================================== */
/* Fuzz target                                                                                    */
/* ============================================================================================== */

// TODO: This could check `EVEX`/`MVEX` stuff as well
void ZydisCompareRequestToInstruction(const ZydisEncoderRequest *request,
    const ZydisDecodedInstruction *insn, const ZydisDecodedOperand* operands, const ZyanU8 *insn_bytes)
{
    // Special case, `xchg rAX, rAX` is an alias for `NOP`
    if ((request->mnemonic == ZYDIS_MNEMONIC_XCHG) &&
        (request->operand_count == 2) &&
        (request->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) &&
        (request->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) &&
        (request->operands[0].reg.value == request->operands[1].reg.value) &&
        (insn->mnemonic == ZYDIS_MNEMONIC_NOP))
    {
        switch (request->operands[0].reg.value)
        {
        case ZYDIS_REGISTER_AX:
        case ZYDIS_REGISTER_EAX:
        case ZYDIS_REGISTER_RAX:
            return;
        default:
            break;
        }
    }

    // Handle possible KNC overlap
    ZydisDecodedInstruction knc_insn;
    ZydisDecodedOperand knc_operands[ZYDIS_MAX_OPERAND_COUNT];
    if (request->mnemonic != insn->mnemonic)
    {
        ZydisDecoder decoder;
        ZydisStackWidth stack_width = (ZydisStackWidth)(insn->stack_width >> 5);
        if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, insn->machine_mode, stack_width)))
        {
            fputs("Failed to initialize decoder\n", ZYAN_STDERR);
            abort();
        }
        if (!ZYAN_SUCCESS(ZydisDecoderEnableMode(&decoder, ZYDIS_DECODER_MODE_KNC, ZYAN_TRUE)))
        {
            fputs("Failed to enable KNC mode\n", ZYAN_STDERR);
            abort();
        }
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, insn_bytes, insn->length, &knc_insn,
            knc_operands)))
        {
            fputs("Failed to decode instruction\n", ZYAN_STDERR);
            abort();
        }
        insn = &knc_insn;
        operands = knc_operands;
    }

    ZyanBool prefixes_match = ((insn->attributes & request->prefixes) == request->prefixes);
    if (!prefixes_match &&
        (request->machine_mode != ZYDIS_MACHINE_MODE_LONG_64) &&
        (request->prefixes & ZYDIS_ATTRIB_HAS_SEGMENT_DS))
    {
        // Encoder allows specifying DS override even when it might be interpreted as NOTRACK
        ZyanU64 acceptable_prefixes = (request->prefixes & (~ZYDIS_ATTRIB_HAS_SEGMENT_DS)) |
                                      ZYDIS_ATTRIB_HAS_NOTRACK;
        prefixes_match = ((insn->attributes & acceptable_prefixes) == acceptable_prefixes);
    }
    if ((request->machine_mode != insn->machine_mode) ||
        (request->mnemonic != insn->mnemonic) ||
        (request->operand_count != insn->operand_count_visible) ||
        !prefixes_match)
    {
        fputs("Basic instruction attributes mismatch\n", ZYAN_STDERR);
        abort();
    }

    for (ZyanU8 i = 0; i < insn->operand_count_visible; ++i)
    {
        const ZydisEncoderOperand *op1 = &request->operands[i];
        const ZydisDecodedOperand *op2 = &operands[i];
        if (op1->type != op2->type)
        {
            fprintf(ZYAN_STDERR, "Mismatch for operand %u\n", i);
            abort();
        }
        switch (op1->type)
        {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            if (op1->reg.value != op2->reg.value)
            {
                fprintf(ZYAN_STDERR, "Mismatch for register operand %u\n", i);
                abort();
            }
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            if ((op1->mem.base != op2->mem.base) ||
                (op1->mem.index != op2->mem.index) ||
                (op1->mem.scale != op2->mem.scale && op2->mem.type != ZYDIS_MEMOP_TYPE_MIB) ||
                (op1->mem.displacement != op2->mem.disp.value))
            {
                ZyanBool acceptable_mismatch = ZYAN_FALSE;
                if (op1->mem.displacement != op2->mem.disp.value)
                {
                    if ((op2->mem.disp.has_displacement) &&
                        (op1->mem.index == ZYDIS_REGISTER_NONE) &&
                        ((op1->mem.base == ZYDIS_REGISTER_NONE) ||
                         (op1->mem.base == ZYDIS_REGISTER_EIP) ||
                         (op1->mem.base == ZYDIS_REGISTER_RIP)))
                    {
                        ZyanU64 addr;
                        ZydisCalcAbsoluteAddress(insn, op2, 0, &addr);
                        acceptable_mismatch = ((ZyanU64)op1->mem.displacement == addr);
                    }
                    if ((insn->machine_mode == ZYDIS_MACHINE_MODE_REAL_16) ||
                        (insn->machine_mode == ZYDIS_MACHINE_MODE_LEGACY_16) ||
                        (insn->machine_mode == ZYDIS_MACHINE_MODE_LONG_COMPAT_16) ||
                        (insn->stack_width == 16) ||
                        (insn->address_width == 16))
                    {
                        acceptable_mismatch = ((op1->mem.displacement & 0xFFFF) ==
                            (op2->mem.disp.value & 0xFFFF));
                    }
                }
                if (!acceptable_mismatch)
                {
                    fprintf(ZYAN_STDERR, "Mismatch for memory operand %u\n", i);
                    abort();
                }
            }
            break;
        case ZYDIS_OPERAND_TYPE_POINTER:
            if ((op1->ptr.segment != op2->ptr.segment) ||
                (op1->ptr.offset != op2->ptr.offset))
            {
                fprintf(ZYAN_STDERR, "Mismatch for pointer operand %u\n", i);
                abort();
            }
            break;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            if (op1->imm.u != op2->imm.value.u)
            {
                ZyanBool acceptable_mismatch = ZYAN_FALSE;
                if ((insn->meta.category == ZYDIS_CATEGORY_DATAXFER) ||
                    (insn->meta.category == ZYDIS_CATEGORY_LOGICAL))
                {
                    if (op2->size < 64)
                    {
                        ZyanU64 mask = (1ULL << op2->size) - 1;
                        acceptable_mismatch =
                            (op1->imm.u & mask) == (op2->imm.value.u & mask);
                    }
                    else
                    {
                        acceptable_mismatch = op1->imm.u == op2->imm.value.u;
                    }
                }
                if (!acceptable_mismatch)
                {
                    fprintf(ZYAN_STDERR, "Mismatch for immediate operand %u\n", i);
                    abort();
                }
            }
            break;
        default:
            fprintf(ZYAN_STDERR, "Invalid operand type for operand %u\n", i);
            abort();
        }
    }
}

ZYAN_NO_SANITIZE("enum")
int ZydisFuzzTarget(ZydisStreamRead read_fn, void *stream_ctx)
{
    ZydisEncoderRequest request;
    if (read_fn(stream_ctx, (ZyanU8 *)&request, sizeof(request)) != sizeof(request))
    {
        ZYDIS_MAYBE_FPUTS("Not enough bytes to fuzz\n", ZYAN_STDERR);
        return EXIT_SUCCESS;
    }

    // Sanitization greatly improves coverage, without it most inputs will fail at basic checks
    // inside `ZydisEncoderCheckRequestSanity`
    request.operand_count %= ZYDIS_ENCODER_MAX_OPERANDS + 1;
    ZYDIS_SANITIZE_MASK32(request.allowed_encodings, ZydisEncodableEncoding,
        ZYDIS_ENCODABLE_ENCODING_MAX_VALUE);
    ZYDIS_SANITIZE_MASK64(request.prefixes, ZydisInstructionAttributes, ZYDIS_ENCODABLE_PREFIXES);
    ZYDIS_SANITIZE_ENUM(request.machine_mode, ZydisMachineMode, ZYDIS_MACHINE_MODE_MAX_VALUE);
    ZYDIS_SANITIZE_ENUM(request.mnemonic, ZydisMnemonic, ZYDIS_MNEMONIC_MAX_VALUE);
    ZYDIS_SANITIZE_ENUM(request.branch_type, ZydisBranchType, ZYDIS_BRANCH_TYPE_MAX_VALUE);
    ZYDIS_SANITIZE_ENUM(request.branch_width, ZydisBranchWidth, ZYDIS_BRANCH_WIDTH_MAX_VALUE);
    ZYDIS_SANITIZE_ENUM(request.address_size_hint, ZydisAddressSizeHint,
        ZYDIS_ADDRESS_SIZE_HINT_MAX_VALUE);
    ZYDIS_SANITIZE_ENUM(request.operand_size_hint, ZydisOperandSizeHint,
        ZYDIS_OPERAND_SIZE_HINT_MAX_VALUE);
    ZYDIS_SANITIZE_ENUM(request.evex.broadcast, ZydisBroadcastMode, ZYDIS_BROADCAST_MODE_MAX_VALUE);
    ZYDIS_SANITIZE_ENUM(request.evex.rounding, ZydisRoundingMode, ZYDIS_ROUNDING_MODE_MAX_VALUE);
    ZYDIS_SANITIZE_ENUM(request.mvex.broadcast, ZydisBroadcastMode, ZYDIS_BROADCAST_MODE_MAX_VALUE);
    ZYDIS_SANITIZE_ENUM(request.mvex.conversion, ZydisConversionMode,
        ZYDIS_CONVERSION_MODE_MAX_VALUE);
    ZYDIS_SANITIZE_ENUM(request.mvex.rounding, ZydisRoundingMode, ZYDIS_ROUNDING_MODE_MAX_VALUE);
    ZYDIS_SANITIZE_ENUM(request.mvex.swizzle, ZydisSwizzleMode, ZYDIS_SWIZZLE_MODE_MAX_VALUE);
    for (ZyanU8 i = 0; i < request.operand_count; ++i)
    {
        ZydisEncoderOperand *op = &request.operands[i];
        op->type = (ZydisOperandType)(ZYDIS_OPERAND_TYPE_REGISTER +
            ((ZyanUSize)op->type % ZYDIS_OPERAND_TYPE_MAX_VALUE));
        switch (op->type)
        {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            ZYDIS_SANITIZE_ENUM(op->reg.value, ZydisRegister, ZYDIS_REGISTER_MAX_VALUE);
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            ZYDIS_SANITIZE_ENUM(op->mem.base, ZydisRegister, ZYDIS_REGISTER_MAX_VALUE);
            ZYDIS_SANITIZE_ENUM(op->mem.index, ZydisRegister, ZYDIS_REGISTER_MAX_VALUE);
            break;
        case ZYDIS_OPERAND_TYPE_POINTER:
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            break;
        default:
            ZYAN_UNREACHABLE;
        }
    }

    ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize encoded_length = sizeof(encoded_instruction);
    ZyanStatus status = ZydisEncoderEncodeInstruction(&request, encoded_instruction,
        &encoded_length);
    if (!ZYAN_SUCCESS(status))
    {
        return EXIT_SUCCESS;
    }

    ZydisStackWidth stack_width;
    switch (request.machine_mode)
    {
    case ZYDIS_MACHINE_MODE_LONG_64:
        stack_width = ZYDIS_STACK_WIDTH_64;
        break;
    case ZYDIS_MACHINE_MODE_LONG_COMPAT_32:
    case ZYDIS_MACHINE_MODE_LEGACY_32:
        stack_width = ZYDIS_STACK_WIDTH_32;
        break;
    case ZYDIS_MACHINE_MODE_LONG_COMPAT_16:
    case ZYDIS_MACHINE_MODE_LEGACY_16:
    case ZYDIS_MACHINE_MODE_REAL_16:
        stack_width = ZYDIS_STACK_WIDTH_16;
        break;
    default:
        ZYAN_UNREACHABLE;
    }

    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, request.machine_mode, stack_width)))
    {
        fputs("Failed to initialize decoder\n", ZYAN_STDERR);
        abort();
    }

    if (request.mnemonic == ZYDIS_MNEMONIC_UD0 && request.operand_count == 0)
    {
        status = ZydisDecoderEnableMode(&decoder, ZYDIS_DECODER_MODE_UD0_COMPAT, ZYAN_TRUE);
        if (!ZYAN_SUCCESS(status))
        {
            fputs("Failed to enable UD0_COMPAT mode\n", ZYAN_STDERR);
            abort();
        }
    }

    ZydisDecodedInstruction insn1;
    ZydisDecodedOperand operands1[ZYDIS_MAX_OPERAND_COUNT];
    status = ZydisDecoderDecodeFull(&decoder, encoded_instruction, encoded_length, &insn1,
        operands1);
    if (!ZYAN_SUCCESS(status))
    {
        fputs("Failed to decode instruction\n", ZYAN_STDERR);
        abort();
    }

    ZydisCompareRequestToInstruction(&request, &insn1, operands1, encoded_instruction);
    ZydisReEncodeInstruction(&decoder, &insn1, operands1, insn1.operand_count, 
        encoded_instruction);

    return EXIT_SUCCESS;
}

/* ============================================================================================== */
