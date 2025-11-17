# Zydis Examples

## Decoder

We currently don't have any examples that specifically only demonstrate using the decoder, but all formatter examples also demonstrate decoding instructions. Additionally, the [`ZydisInfo.c`](../tools/ZydisInfo.c) and [`ZydisDisasm.c`](../tools/ZydisDisasm.c) examples in the [tools](../tools) directory serve as additional examples for both decoding and formatting.

## Formatter

### [Formatter01](./Formatter01.c)
Demonstrates basic hooking functionality of the `ZydisFormatter` class by implementing a custom symbol-resolver.

### [Formatter02](./Formatter02.c)
Demonstrates basic hooking functionality of the `ZydisFormatter` class and the ability to completely omit specific operands.

The example demonstrates the hooking functionality of the `ZydisFormatter` class by rewriting the mnemonics of `(V)CMPPS` and `(V)CMPPD` to their corresponding alias-forms (based on the condition encoded in the immediate operand).

### [Formatter03](./Formatter03.c)
Demonstrates the tokenizing feature of the `ZydisFormatter` class.

## Encoder

### [EncodeFromScratch](./EncodeFromScratch.c)
Example assembling a basic function returning `0x1337` in `rax` from scratch.

### [RewriteCode](./RewriteCode.c)
Demonstrates how to rewrite ("reassemble") instructions.

## Misc

### [ZydisWinKernel](./ZydisWinKernel.c)
Implements an example Windows kernel-mode driver.