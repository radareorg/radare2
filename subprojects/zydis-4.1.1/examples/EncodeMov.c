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
 * Demonstrates encoding a single instruction using the encoder.
 */

#include <stdio.h>
#include <string.h>

#include <Zydis/Zydis.h>

int main(void)
{
    ZydisEncoderRequest req;
    memset(&req, 0, sizeof(req));

    req.mnemonic = ZYDIS_MNEMONIC_MOV;
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    req.operand_count = 2;
    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
    req.operands[0].reg.value = ZYDIS_REGISTER_RAX;
    req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    req.operands[1].imm.u = 0x1337;

    ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize encoded_length = sizeof(encoded_instruction);

    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, encoded_instruction, &encoded_length)))
    {
        puts("Failed to encode instruction");
        return 1;
    }

    for (ZyanUSize i = 0; i < encoded_length; ++i)
    {
        printf("%02X ", encoded_instruction[i]);
    }
    puts("");

    return 0;
}
