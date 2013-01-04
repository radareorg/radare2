// This file is part of Radio-86RK Tools project.
//
// Intel 8080 disassembler.
//
// https://github.com/begoon/rk86-tools
//
// Copyright (C) 2012 Alexander Demin <alexander@demin.ws>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files
// (the "Software"), to deal in the Software without restriction,
// including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software,
// and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <string.h>
#include <stdio.h>
#include <assert.h>

static char *reg[] = { "b", "c", "d", "e", "h", "l", "m", "a" };
static char *rp[] = { "b", "d", "h", "sp" };
static char *push_rp[] = { "b", "d", "h", "psw" };
static char *cond[] = { "nz", "z", "nc", "c", "po", "pe", "p", "m" };
static char *rst[] = { "0", "1", "2", "3", "4", "5", "6", "7" };

struct arg_t {
  int type; /* 1 - next byte, 2 - next word, 3 - in opcode */
  int shift;
  int mask;
  char **fmt;
};

static struct opcode_t {
  unsigned char cmd;
  int size;
  char *name;
  struct arg_t arg1, arg2;
} opcodes[] = {
  { 0x76, 1, "hlt" },
  { 0x06, 2, "mvi", { 3, 3, 7, reg }, { 1 } },
  { 0xc3, 3, "jmp", { 2 } },
  { 0x40, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } },
  { 0x01, 3, "lxi", { 3, 4, 3, rp }, { 2 } },
  { 0x32, 3, "sta", { 2 } },
  { 0x3a, 3, "lda", { 2 } },
  { 0x2a, 3, "lhld", { 2 } },
  { 0x22, 3, "shld", { 2 } },
  { 0x0a, 1, "ldax", { 3, 4, 1, rp } },
  { 0x02, 1, "stax", { 3, 4, 1, rp } },
  { 0xeb, 1, "xchg" },
  { 0xf9, 1, "sphl" },
  { 0xe3, 1, "xthl" },
  { 0xc5, 1, "push", { 3, 4, 3, push_rp } },
  { 0xc1, 1, "pop", { 3, 4, 3, push_rp } },
  { 0xdb, 2, "in", { 1 } },
  { 0xd3, 2, "out", { 1 } },
  { 0x03, 1, "inx", { 3, 4, 3, rp } },
  { 0x0b, 1, "dcx", { 3, 4, 3, rp } },
  { 0x04, 1, "inr", { 3, 3, 7, reg } },
  { 0x05, 1, "dcr", { 3, 3, 7, reg } },
  { 0x09, 1, "dad", { 3, 4, 3, rp } },
  { 0x2f, 1, "cma" },
  { 0x07, 1, "rlc" },
  { 0x0f, 1, "rrc" },
  { 0x17, 1, "ral" },
  { 0x1f, 1, "rar" },
  { 0xfb, 1, "ei" },
  { 0xf3, 1, "di" },
  { 0x00, 1, "nop" },
  { 0x37, 1, "stc" },
  { 0x3f, 1, "cmc" },
  { 0xe9, 1, "pchl" },
  { 0x27, 1, "daa" },
  { 0xcd, 3, "call", { 2 } },
  { 0xc9, 1, "ret" },
  { 0xc7, 1, "rst", { 3, 3, 7, rst } },
  { 0xc0, 1, "r", { 3, 3, 7, cond } },
  { 0xc2, 3, "j", { 3, 3, 7, cond }, { 2 } },
  { 0xc4, 3, "c", { 3, 3, 7, cond }, { 2 } },
  { 0x80, 1, "add", { 3, 0, 7, reg } },
  { 0x80|0x46, 2, "adi", { 1 } },
  { 0x88, 1, "adc", { 3, 0, 7, reg } },
  { 0x88|0x46, 2, "aci", { 1 } },
  { 0x90, 1, "sub", { 3, 0, 7, reg } },
  { 0x90|0x46, 2, "sui", { 1 } },
  { 0x98, 1, "sbb", { 3, 0, 7, reg } },
  { 0x98|0x46, 2, "sbi", { 1 } },
  { 0xa0, 1, "ana", { 3, 0, 7, reg } },
  { 0xa0|0x46, 2, "ani", { 1 } },
  { 0xa8, 1, "xra", { 3, 0, 7, reg } },
  { 0xa8|0x46, 2, "xri", { 1 } },
  { 0xb0, 1, "ora", { 3, 0, 7, reg } },
  { 0xb0|0x46, 2, "ori", { 1 } },
  { 0xb8, 1, "cmp", { 3, 0, 7, reg } },
  { 0xb8|0x46, 2, "cpi", { 1 } },
  { 0x00, 1, "nop" },
  { 0x00, 0 }
};

static void arg(char* s, int const cmd, struct arg_t const* arg, int val) {
  if (arg->type == 3) {
    strcat(s, arg->fmt[(cmd >> arg->shift) & arg->mask]);
  } else {
    if (arg->type == 1)
      sprintf(s, "%02X", val & 0xff);
    else if (arg->type == 2)
      sprintf(s, "%04X", val);
  }
}

static int i8080_disasm(unsigned char const* const code, char* text, int text_sz) {
  int const cmd = code[0];
  int const p = code[1] | (code[2] << 8);

  struct opcode_t const *op;
  for (op = &opcodes[0]; op->size; ++op) {
    int const grp = cmd &
      ~((op->arg1.mask << op->arg1.shift) | 
       (op->arg2.mask << op->arg2.shift));
    int const branch = (grp == 0xc0 || grp == 0xc2 || grp == 0xc4);
    if (grp == op->cmd) {
      strcpy(text, op->name);
      if (!branch) strcat(text, " ");
      arg(text + strlen(text), cmd, &op->arg1, p);
      if (op->arg2.type != 0) strcat(text, (branch ? " " : ", "));
      arg(text + strlen(text), cmd, &op->arg2, p);
      return op->size;
    }
  }
  snprintf(text, text_sz, "db 0x%02x", cmd);
  return 1;
}

