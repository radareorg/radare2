/* radare - LGPL - Copyright 2022 - pancake */

#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_asm.h>

static const char *pseudo_rules[] = {
	// Arithmetic operations
	"add/0/push(pop() + pop())",
	"sub/0/push(pop() - pop())",
	"mul/0/push(pop() * pop())",
	"div/0/push(pop() / pop())",
	"mod/0/push(pop() % pop())",
	"sdiv/0/push((signed)pop() / (signed)pop())",
	"smod/0/push((signed)pop() % (signed)pop())",
	"exp/0/push(pow(pop(), pop()))",
	"mulmod/0/push((pop() * pop()) % pop())",
	"not/0/push(~pop())",
	"or/0/push(pop() | pop())",
	"gt/0/push(pop() > pop())",
	"lt/0/push(pop() < pop())",
	"sgt/0/push((signed)pop() > (signed)pop())",

	// Stack operations
	"dup1/0/push(stack[sp-1])",
	"dup2/0/push(stack[sp-2])",
	"dup4/0/push(stack[sp-4])",
	"dup5/0/push(stack[sp-5])",
	"dup6/0/push(stack[sp-6])",
	"dup8/0/push(stack[sp-8])",
	"dup9/0/push(stack[sp-9])",
	"dup10/0/push(stack[sp-10])",
	"dup12/0/push(stack[sp-12])",
	"dup14/0/push(stack[sp-14])",
	"dup16/0/push(stack[sp-16])",
	"swap1/0/swap(stack[sp-1], stack[sp-2])",
	"swap2/0/swap(stack[sp-1], stack[sp-3])",
	"swap3/0/swap(stack[sp-1], stack[sp-4])",
	"swap4/0/swap(stack[sp-1], stack[sp-5])",
	"swap6/0/swap(stack[sp-1], stack[sp-7])",
	"swap9/0/swap(stack[sp-1], stack[sp-10])",
	"swap15/0/swap(stack[sp-1], stack[sp-16])",
	"swap16/0/swap(stack[sp-1], stack[sp-17])",

	// Push operations
	"push4/1/push($1)",
	"push6/1/push($1)",
	"push7/1/push($1)",
	"push8/1/push($1)",
	"push10/1/push($1)",
	"push14/1/push($1)",
	"push16/1/push($1)",
	"push19/1/push($1)",
	"push21/1/push($1)",
	"push22/1/push($1)",
	"push25/1/push($1)",
	"push30/1/push($1)",
	"push32/1/push($1)",

	// Memory operations
	"mload/0/push(memory[pop()])",
	"mstore8/0/memory[pop()] = pop() & 0xff",
	"sload/0/push(storage[pop()])",
	"sstore/0/storage[pop()] = pop()",
	"codecopy/0/memcpy(memory + pop(), code + pop(), pop())",
	"calldatacopy/0/memcpy(memory + pop(), calldata + pop(), pop())",
	"calldataload/0/push(calldata[pop()])",
	"calldatasize/0/push(calldatasize)",
	"returndatacopy/0/memcpy(memory + pop(), returndata + pop(), pop())",
	"returndatasize/0/push(returndatasize)",
	"extcodecopy/0/memcpy(memory + pop(), extcode[pop()] + pop(), pop())",
	"extcodesize/0/push(extcodesize[pop()])",

	// Control flow
	"jump/1/goto $1",
	"jumpdest/0/jumpdest",
	"jumpi/1/if (pop()) goto $1",

	// Calls and creates
	"callcode/0/callcode(gas=pop(), addr=pop(), value=pop(), in=pop(), insize=pop(), out=pop(), outsize=pop())",
	"create/0/create(value=pop(), in=pop(), insize=pop())",
	"delegatecall/0/delegatecall(gas=pop(), addr=pop(), in=pop(), insize=pop(), out=pop(), outsize=pop())",
	"staticcall/0/staticcall(gas=pop(), addr=pop(), in=pop(), insize=pop(), out=pop(), outsize=pop())",

	// System operations
	"balance/0/push(balance[pop()])",
	"blockhash/0/push(blockhash[pop()])",
	"coinbase/0/push(coinbase)",
	"timestamp/0/push(timestamp)",
	"gaslimit/0/push(gaslimit)",
	"gas/0/push(gas)",
	"caller/0/push(caller)",
	"callvalue/0/push(callvalue)",
	"codesize/0/push(codesize)",

	// Logging
	"log0/0/log(memory + pop(), pop())",

	// Termination
	"invalid/0/invalid",
	"stop/0/stop",
	"revert/0/revert(pop(), pop())",
	"suicide/0/suicide(pop())",

	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_evm = {
	.meta = {
		.name = "evm",
		.desc = "evm pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_evm,
	.version = R2_VERSION
};
#endif
