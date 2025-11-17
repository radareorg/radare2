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
 * This file implements an entry point and common functions used by fuzz target projects. To create
 * a new fuzz target add this file to your project and implement `ZydisFuzzTarget` in a separate
 * compilation unit.
 */

#include "ZydisFuzzShared.h"

#ifdef ZYAN_WINDOWS
#   include <fcntl.h>
#   include <io.h>
#endif

#ifdef ZYAN_POSIX
#   include <unistd.h>
#endif

/* ============================================================================================== */
/* Stream reading abstraction                                                                     */
/* ============================================================================================== */

ZyanUSize ZydisStdinRead(void *ctx, ZyanU8* buf, ZyanUSize max_len)
{
    ZYAN_UNUSED(ctx);
#ifdef ZYAN_POSIX
    // `fread` does internal buffering that can result in different code paths to be taken every
    // time we call it. This is detrimental for fuzzing stability in persistent mode. Use direct
    // syscall when possible.
    return read(0, buf, max_len);
#else
    return fread(buf, 1, max_len, ZYAN_STDIN);
#endif
}

#ifdef ZYDIS_LIBFUZZER
typedef struct
{
    ZyanU8 *buf;
    ZyanISize buf_len;
    ZyanISize read_offs;
} ZydisLibFuzzerContext;

ZyanUSize ZydisLibFuzzerRead(void* ctx, ZyanU8* buf, ZyanUSize max_len)
{
    ZydisLibFuzzerContext* c = (ZydisLibFuzzerContext*)ctx;
    ZyanUSize len = ZYAN_MIN((ZyanUSize)(c->buf_len - c->read_offs), max_len);
    // printf("buf_len: %ld, read_offs: %ld, len: %ld, max_len: %ld, ptr: %p\n",
    //     c->buf_len, c->read_offs, len, max_len, c->buf + c->read_offs);
    if (!len)
    {
        return 0;
    }
    ZYAN_MEMCPY(buf, c->buf + c->read_offs, len);
    c->read_offs += len;
    return len;
}
#endif // ZYDIS_LIBFUZZER

/* ============================================================================================== */
/* Shared utility functions                                                                       */
/* ============================================================================================== */

#if !defined(ZYDIS_FUZZ_AFL_FAST) && !defined(ZYDIS_LIBFUZZER)

void ZydisPrintInstruction(const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands, ZyanU8 operand_count, const ZyanU8* instruction_bytes)
{
    switch (instruction->machine_mode)
    {
    case ZYDIS_MACHINE_MODE_LONG_64:
        printf("-64 ");
        break;
    case ZYDIS_MACHINE_MODE_LONG_COMPAT_32:
    case ZYDIS_MACHINE_MODE_LEGACY_32:
        printf("-32 ");
        break;
    case ZYDIS_MACHINE_MODE_LONG_COMPAT_16:
    case ZYDIS_MACHINE_MODE_LEGACY_16:
    case ZYDIS_MACHINE_MODE_REAL_16:
        printf("-16 ");
        break;
    default:
        ZYAN_UNREACHABLE;
    }
    printf("-%u ", instruction->stack_width);

    for (ZyanU8 i = 0; i < instruction->length; ++i)
    {
        printf("%02X", instruction_bytes[i]);
    }

    ZydisFormatter formatter;
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)) ||
        !ZYAN_SUCCESS(ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT,
            ZYAN_TRUE)) ||
        !ZYAN_SUCCESS(ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE,
            ZYAN_TRUE)))
    {
        fputs("Failed to initialize instruction formatter\n", ZYAN_STDERR);
        abort();
    }

    char buffer[256];
    ZydisFormatterFormatInstruction(&formatter, instruction, operands, operand_count, buffer,
        sizeof(buffer), 0, ZYAN_NULL);
    printf(" %s\n", buffer);
}

#endif

// NOTE: This function doesn't validate flag values, yet.
void ZydisValidateEnumRanges(const ZydisDecodedInstruction* insn,
    const ZydisDecodedOperand* operands, ZyanU8 operand_count)
{
#   define ZYDIS_CHECK_ENUM(value, max)                                                            \
    if ((ZyanU64)(value) > (ZyanU64)(max))                                                         \
    {                                                                                              \
        fprintf(stderr, "Value " #value " = 0x%016" PRIX64 " is above expected max " #max          \
            " = 0x%016" PRIX64 "\n", (ZyanU64)(value), (ZyanU64)(max));                            \
        abort();                                                                                   \
    }

    ZYDIS_CHECK_ENUM(insn->length, ZYDIS_MAX_INSTRUCTION_LENGTH);

    ZYDIS_CHECK_ENUM(insn->machine_mode, ZYDIS_MACHINE_MODE_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->mnemonic, ZYDIS_MNEMONIC_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->encoding, ZYDIS_INSTRUCTION_ENCODING_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->opcode_map, ZYDIS_OPCODE_MAP_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->opcode_map, ZYDIS_OPCODE_MAP_MAX_VALUE);

    // Operands.
    for (ZyanU32 i = 0; i < operand_count; ++i)
    {
        const ZydisDecodedOperand* op = &operands[i];
        ZYDIS_CHECK_ENUM(op->type, ZYDIS_OPERAND_TYPE_MAX_VALUE);
        ZYDIS_CHECK_ENUM(op->visibility, ZYDIS_OPERAND_VISIBILITY_MAX_VALUE);
        ZYDIS_CHECK_ENUM(op->encoding, ZYDIS_OPERAND_ENCODING_MAX_VALUE);
        ZYDIS_CHECK_ENUM(op->element_type, ZYDIS_ELEMENT_TYPE_MAX_VALUE);

        switch (op->type)
        {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            ZYDIS_CHECK_ENUM(op->reg.value, ZYDIS_REGISTER_MAX_VALUE);
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            ZYDIS_CHECK_ENUM(op->mem.type, ZYDIS_MEMOP_TYPE_MAX_VALUE);
            ZYDIS_CHECK_ENUM(op->mem.segment, ZYDIS_REGISTER_MAX_VALUE);
            ZYDIS_CHECK_ENUM(op->mem.base, ZYDIS_REGISTER_MAX_VALUE);
            ZYDIS_CHECK_ENUM(op->mem.index, ZYDIS_REGISTER_MAX_VALUE);
            ZYDIS_CHECK_ENUM(op->mem.disp.has_displacement, ZYAN_TRUE);
            break;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            ZYDIS_CHECK_ENUM(op->imm.is_signed, ZYAN_TRUE);
            ZYDIS_CHECK_ENUM(op->imm.is_relative, ZYAN_TRUE);
            break;
        default:
            break;
        }
    }

    // AVX.
    ZYDIS_CHECK_ENUM(insn->avx.mask.mode, ZYDIS_MASK_MODE_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->avx.mask.reg, ZYDIS_REGISTER_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->avx.broadcast.is_static, ZYAN_TRUE);
    ZYDIS_CHECK_ENUM(insn->avx.broadcast.mode, ZYDIS_BROADCAST_MODE_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->avx.rounding.mode, ZYDIS_ROUNDING_MODE_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->avx.swizzle.mode, ZYDIS_SWIZZLE_MODE_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->avx.conversion.mode, ZYDIS_CONVERSION_MODE_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->avx.has_sae, ZYAN_TRUE);
    ZYDIS_CHECK_ENUM(insn->avx.has_eviction_hint, ZYAN_TRUE);

    // Meta.
    ZYDIS_CHECK_ENUM(insn->meta.category, ZYDIS_CATEGORY_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->meta.isa_set, ZYDIS_ISA_SET_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->meta.isa_ext, ZYDIS_ISA_SET_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->meta.branch_type, ZYDIS_BRANCH_TYPE_MAX_VALUE);
    ZYDIS_CHECK_ENUM(insn->meta.exception_class, ZYDIS_EXCEPTION_CLASS_MAX_VALUE);

    // Raw.
    for (ZyanU32 i = 0; i < ZYAN_ARRAY_LENGTH(insn->raw.prefixes); ++i)
    {
        ZYDIS_CHECK_ENUM(insn->raw.prefixes[i].type, ZYDIS_PREFIX_TYPE_MAX_VALUE);
    }
    for (ZyanU32 i = 0; i < ZYAN_ARRAY_LENGTH(insn->raw.imm); ++i)
    {
        ZYDIS_CHECK_ENUM(insn->raw.imm[i].is_signed, ZYAN_TRUE);
        ZYDIS_CHECK_ENUM(insn->raw.imm[i].is_relative, ZYAN_TRUE);
    }

#   undef ZYDIS_CHECK_ENUM
}

void ZydisValidateInstructionIdentity(const ZydisDecodedInstruction* insn1,
    const ZydisDecodedOperand* operands1, const ZydisDecodedInstruction* insn2,
    const ZydisDecodedOperand* operands2)
{
    // TODO: Probably a good idea to input validate operand_counts to this function
    // TODO: I don't like accessing buffers without having their actual sizes available...

    // Special case, `xchg rAX, rAX` is an alias for `NOP`
    if ((insn1->mnemonic == ZYDIS_MNEMONIC_XCHG) &&
        (insn1->operand_count == 2) &&
        (operands1[0].type == ZYDIS_OPERAND_TYPE_REGISTER) &&
        (operands1[1].type == ZYDIS_OPERAND_TYPE_REGISTER) &&
        (operands1[0].reg.value == operands1[1].reg.value) &&
        (insn2->mnemonic == ZYDIS_MNEMONIC_NOP))
    {
        switch (operands1[0].reg.value)
        {
        case ZYDIS_REGISTER_AX:
        case ZYDIS_REGISTER_EAX:
        case ZYDIS_REGISTER_RAX:
            return;
        default:
            break;
        }
    }

    ZydisSwizzleMode swizzle1 = insn1->avx.swizzle.mode == ZYDIS_SWIZZLE_MODE_DCBA ?
        ZYDIS_SWIZZLE_MODE_INVALID : insn1->avx.swizzle.mode;
    ZydisSwizzleMode swizzle2 = insn2->avx.swizzle.mode == ZYDIS_SWIZZLE_MODE_DCBA ?
        ZYDIS_SWIZZLE_MODE_INVALID : insn2->avx.swizzle.mode;
    if ((insn1->machine_mode != insn2->machine_mode) ||
        (insn1->mnemonic != insn2->mnemonic) ||
        (insn1->stack_width != insn2->stack_width) ||
        (insn1->operand_count != insn2->operand_count) ||
        (insn1->avx.mask.mode != insn2->avx.mask.mode) ||
        (insn1->avx.broadcast.is_static != insn2->avx.broadcast.is_static) ||
        (insn1->avx.broadcast.mode != insn2->avx.broadcast.mode) ||
        (insn1->avx.conversion.mode != insn2->avx.conversion.mode) ||
        (insn1->avx.rounding.mode != insn2->avx.rounding.mode) ||
        (insn1->avx.has_sae != insn2->avx.has_sae) ||
        (insn1->avx.has_eviction_hint != insn2->avx.has_eviction_hint) ||
        (swizzle1 != swizzle2))
    {
        fputs("Basic instruction attributes mismatch\n", ZYAN_STDERR);
        abort();
    }

    for (ZyanU8 i = 0; i < insn1->operand_count; ++i)
    {
        const ZydisDecodedOperand *op1 = &operands1[i];
        const ZydisDecodedOperand *op2 = &operands2[i];
        if ((op1->type != op2->type) ||
            (op1->size != op2->size && op1->type != ZYDIS_OPERAND_TYPE_IMMEDIATE))
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
        {
            // Usually this check is done after verifying instruction identity but in this case
            // we have to fail early
            if (insn1->length < insn2->length)
            {
                fputs("Suboptimal output size detected\n", ZYAN_STDERR);
                abort();
            }
            ZyanU64 addr1, addr2;
            ZyanStatus status1 = ZydisCalcAbsoluteAddress(insn1, op1, 0, &addr1);
            ZyanStatus status2 = ZydisCalcAbsoluteAddress(insn2, op2,
                insn1->length - insn2->length, &addr2);
            ZyanBool addresses_match = ZYAN_FALSE;
            if (ZYAN_SUCCESS(status1) && ZYAN_SUCCESS(status2))
            {
                if (addr1 != addr2)
                {
                    fprintf(ZYAN_STDERR, "Mismatch for memory operand %u (absolute address)\n", i);
                    abort();
                }
                addresses_match = ZYAN_TRUE;
            }
            if ((op1->mem.type != op2->mem.type) ||
                (op1->mem.segment != op2->mem.segment) ||
                (op1->mem.base != op2->mem.base) ||
                (op1->mem.index != op2->mem.index) ||
                ((op1->mem.scale != op2->mem.scale) && (op1->mem.type != ZYDIS_MEMOP_TYPE_MIB)) ||
                ((op1->mem.disp.value != op2->mem.disp.value) && !addresses_match))
            {
                fprintf(ZYAN_STDERR, "Mismatch for memory operand %u\n", i);
                abort();
            }
            break;
        }
        case ZYDIS_OPERAND_TYPE_POINTER:
            if ((op1->ptr.segment != op2->ptr.segment) ||
                (op1->ptr.offset != op2->ptr.offset))
            {
                fprintf(ZYAN_STDERR, "Mismatch for pointer operand %u\n", i);
                abort();
            }
            break;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            if ((op1->imm.is_relative != op2->imm.is_relative) ||
                (op1->imm.is_signed != op2->imm.is_signed) ||
                (op1->imm.value.u != op2->imm.value.u))
            {
                ZyanBool acceptable_mismatch = ZYAN_FALSE;
                if ((insn1->meta.category == ZYDIS_CATEGORY_DATAXFER) ||
                    (insn1->meta.category == ZYDIS_CATEGORY_LOGICAL))
                {
                    const ZyanU16 size = ZYAN_MAX(op1->size, op2->size);
                    if (size < 64)
                    {
                        const ZyanU64 mask = (1ULL << size) - 1;
                        acceptable_mismatch =
                            (op1->imm.value.u & mask) == (op2->imm.value.u & mask);
                    }
                    else
                    {
                        acceptable_mismatch = op1->imm.value.u == op2->imm.value.u;
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

#if !defined(ZYDIS_DISABLE_ENCODER)

static void ZydisReEncodeInstructionAbsolute(ZydisEncoderRequest* req,
    const ZydisDecodedInstruction* insn2, const ZydisDecodedOperand* insn2_operands,
    const ZyanU8* insn2_bytes)
{
    ZyanU64 runtime_address;
    switch (insn2->address_width)
    {
    case 16:
        runtime_address = (ZyanU64)(ZyanU16)ZYAN_INT16_MIN;
        break;
    case 32:
        runtime_address = (ZyanU64)(ZyanU32)ZYAN_INT32_MIN;
        break;
    case 64:
        runtime_address = (ZyanU64)ZYAN_INT64_MIN;
        break;
    default:
        ZYAN_UNREACHABLE;
    }
    if ((insn2->machine_mode != ZYDIS_MACHINE_MODE_LONG_64) && (insn2->operand_width == 16))
    {
        runtime_address = (ZyanU64)(ZyanU16)ZYAN_INT16_MIN;
    }
    runtime_address -= insn2->length;

    ZyanBool has_relative = ZYAN_FALSE;
    for (ZyanU8 i = 0; i < req->operand_count; ++i)
    {
        const ZydisDecodedOperand *decoded_op = &insn2_operands[i];
        ZydisEncoderOperand *op = &req->operands[i];
        ZyanU64 *dst_address = ZYAN_NULL;
        switch (op->type)
        {
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            if (decoded_op->imm.is_relative)
            {
                dst_address = &op->imm.u;
            }
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            if ((decoded_op->mem.base == ZYDIS_REGISTER_EIP) ||
                (decoded_op->mem.base == ZYDIS_REGISTER_RIP))
            {
                dst_address = (ZyanU64 *)&op->mem.displacement;
            }
            break;
        default:
            break;
        }
        if (!dst_address)
        {
            continue;
        }
        has_relative = ZYAN_TRUE;
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(insn2, decoded_op, runtime_address,
            dst_address)))
        {
            fputs("ZydisCalcAbsoluteAddress has failed\n", ZYAN_STDERR);
            abort();
        }
    }
    if (!has_relative)
    {
        return;
    }

    ZyanU8 insn1_bytes[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize insn1_length = sizeof(insn1_bytes);
    ZyanStatus status = ZydisEncoderEncodeInstructionAbsolute(req, insn1_bytes, &insn1_length,
        runtime_address);
    if (!ZYAN_SUCCESS(status))
    {
        fputs("Failed to re-encode instruction (absolute)\n", ZYAN_STDERR);
        abort();
    }
    if (insn1_length != insn2->length || ZYAN_MEMCMP(insn1_bytes, insn2_bytes, insn2->length))
    {
        fputs("Instruction mismatch (absolute)\n", ZYAN_STDERR);
        abort();
    }
}

void ZydisReEncodeInstruction(const ZydisDecoder *decoder, const ZydisDecodedInstruction *insn1,
    const ZydisDecodedOperand* operands1, ZyanU8 operand_count, const ZyanU8 *insn1_bytes)
{
    ZydisPrintInstruction(insn1, operands1, operand_count, insn1_bytes);
    ZydisValidateEnumRanges(insn1, operands1, operand_count);

    ZYAN_ASSERT(operand_count >= insn1->operand_count_visible);

    ZydisEncoderRequest request;
    ZyanStatus status = ZydisEncoderDecodedInstructionToEncoderRequest(insn1, operands1,
        insn1->operand_count_visible, &request);
    if (!ZYAN_SUCCESS(status))
    {
        fputs("ZydisEncoderDecodedInstructionToEncoderRequest failed\n", ZYAN_STDERR);
        abort();
    }

    ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize encoded_length = sizeof(encoded_instruction);
    status = ZydisEncoderEncodeInstruction(&request, encoded_instruction, &encoded_length);
    if (!ZYAN_SUCCESS(status))
    {
        fputs("Failed to re-encode instruction\n", ZYAN_STDERR);
        abort();
    }

    ZydisDecodedInstruction insn2;
    ZydisDecodedOperand operands2[ZYDIS_MAX_OPERAND_COUNT];
    status = ZydisDecoderDecodeFull(decoder, encoded_instruction, encoded_length, &insn2,
        operands2);
    if (!ZYAN_SUCCESS(status))
    {
        fputs("Failed to decode re-encoded instruction\n", ZYAN_STDERR);
        abort();
    }

    ZydisPrintInstruction(&insn2, operands2, insn2.operand_count_visible, encoded_instruction);
    ZydisValidateEnumRanges(&insn2, operands2, insn2.operand_count_visible);
    ZydisValidateInstructionIdentity(insn1, operands1, &insn2, operands2);

    if (insn2.length > insn1->length)
    {
        fputs("Suboptimal output size detected\n", ZYAN_STDERR);
        abort();
    }

    ZydisReEncodeInstructionAbsolute(&request, &insn2, operands2, encoded_instruction);
}

#endif

/* ============================================================================================== */
/* Entry point                                                                                    */
/* ============================================================================================== */

int ZydisFuzzerInit(void)
{
    if (ZydisGetVersion() != ZYDIS_VERSION)
    {
        fputs("Invalid Zydis version\n", ZYAN_STDERR);
        return EXIT_FAILURE;
    }

#ifdef ZYAN_WINDOWS
    // The `stdin` pipe uses text-mode on Windows platforms by default. We need it to be opened in
    // binary mode
    (void)_setmode(_fileno(ZYAN_STDIN), _O_BINARY);
#endif

    return EXIT_SUCCESS;
}

#ifdef ZYDIS_LIBFUZZER

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    ZYAN_UNUSED(argc);
    ZYAN_UNUSED(argv);

    return ZydisFuzzerInit();
}

int LLVMFuzzerTestOneInput(ZyanU8 *buf, ZyanUSize len)
{
    ZydisLibFuzzerContext ctx;
    ctx.buf = buf;
    ctx.buf_len = len;
    ctx.read_offs = 0;

    ZydisFuzzTarget(&ZydisLibFuzzerRead, &ctx);
    return 0;
}

#ifdef __cplusplus
} // extern "C"
#endif

#else // !ZYDIS_LIBFUZZER

int main(void)
{
    if (ZydisFuzzerInit() != EXIT_SUCCESS)
    {
        return EXIT_FAILURE;
    }

#ifdef ZYDIS_FUZZ_AFL_FAST
    while (__AFL_LOOP(1000))
    {
        ZydisFuzzTarget(&ZydisStdinRead, ZYAN_NULL);
    }
    return EXIT_SUCCESS;
#else
    return ZydisFuzzTarget(&ZydisStdinRead, ZYAN_NULL);
#endif
}

#endif // ZYDIS_LIBFUZZER

/* ============================================================================================== */
