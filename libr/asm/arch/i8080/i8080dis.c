#include <string.h>
#include <stdio.h>
#include <assert.h>

static char *reg[] = { "B", "C", "D", "E", "H", "L", "M", "A" };
static char *rp[] = { "B", "D", "H", "SP" };
static char *push_rp[] = { "B", "D", "H", "PSW" };
static char *cond[] = { "NZ", "Z", "NC", "C", "PO", "PE", "P", "M" };
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
  { 0x76, 1, "HLT" },
  { 0x06, 2, "MVI", { 3, 3, 7, reg }, { 1 } },
  { 0xc3, 3, "JMP", { 2 } },
  { 0x40, 1, "MOV", { 3, 3, 7, reg }, { 3, 0, 7, reg } },
  { 0x01, 3, "LXI", { 3, 4, 3, rp }, { 2 } },
  { 0x32, 3, "STA", { 2 } },
  { 0x3a, 3, "LDA", { 2 } },
  { 0x2a, 3, "LHLD", { 2 } },
  { 0x22, 3, "SHLD", { 2 } },
  { 0x0a, 1, "LDAX", { 3, 4, 1, rp } },
  { 0x02, 1, "STAX", { 3, 4, 1, rp } },
  { 0xeb, 1, "XCHG" },
  { 0xf9, 1, "SPHL" },
  { 0xe3, 1, "XTHL" },
  { 0xc5, 1, "PUSH", { 3, 4, 3, push_rp } },
  { 0xc1, 1, "POP", { 3, 4, 3, push_rp } },
  { 0xdb, 2, "IN", { 1 } },
  { 0xd3, 2, "OUT", { 1 } },
  { 0x03, 1, "INX", { 3, 4, 3, rp } },
  { 0x0b, 1, "DCX", { 3, 4, 3, rp } },
  { 0x04, 1, "INR", { 3, 3, 7, reg } },
  { 0x05, 1, "DCR", { 3, 3, 7, reg } },
  { 0x09, 1, "DAD", { 3, 4, 3, rp } },
  { 0x2f, 1, "CMA" },
  { 0x07, 1, "RLC" },
  { 0x0f, 1, "RRC" },
  { 0x17, 1, "RAL" },
  { 0x1f, 1, "RAR" },
  { 0xfb, 1, "EI" },
  { 0xf3, 1, "DI" },
  { 0x00, 1, "NOP" },
  { 0x37, 1, "STC" },
  { 0x3f, 1, "CMC" },
  { 0xe9, 1, "PCHL" },
  { 0x27, 1, "DAA" },
  { 0xcd, 3, "CALL", { 2 } },
  { 0xc9, 1, "RET" },
  { 0xc7, 1, "RST", { 3, 3, 7, rst } },
  { 0xc0, 1, "R", { 3, 3, 7, cond } },
  { 0xc2, 3, "J", { 3, 3, 7, cond }, { 2 } },
  { 0xc4, 3, "C", { 3, 3, 7, cond }, { 2 } },
  { 0x80, 1, "ADD", { 3, 0, 7, reg } },
  { 0x80|0x46, 2, "ADI", { 1 } },
  { 0x88, 1, "ADC", { 3, 0, 7, reg } },
  { 0x88|0x46, 2, "ACI", { 1 } },
  { 0x90, 1, "SUB", { 3, 0, 7, reg } },
  { 0x90|0x46, 2, "SUI", { 1 } },
  { 0x98, 1, "SBB", { 3, 0, 7, reg } },
  { 0x98|0x46, 2, "SBI", { 1 } },
  { 0xa0, 1, "ANA", { 3, 0, 7, reg } },
  { 0xa0|0x46, 2, "ANI", { 1 } },
  { 0xa8, 1, "XRA", { 3, 0, 7, reg } },
  { 0xa8|0x46, 2, "XRI", { 1 } },
  { 0xb0, 1, "ORA", { 3, 0, 7, reg } },
  { 0xb0|0x46, 2, "ORI", { 1 } },
  { 0xb8, 1, "CMP", { 3, 0, 7, reg } },
  { 0xb8|0x46, 2, "CPI", { 1 } },
  { 0x00, 1, "NOP" },
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

int i8080_disasm(unsigned char const* const code, char* text, int text_sz) {
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
      if (op->arg2.type != 0) strcat(text, (branch ? " " : ","));
      arg(text + strlen(text), cmd, &op->arg2, p);
      return op->size;
    }
  }
  snprintf(text, text_sz, "DB %02X", cmd);
  return 1;
}

