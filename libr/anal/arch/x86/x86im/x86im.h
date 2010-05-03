//////////////////////////////////////////////////////////////
//
// x86 Instruction Manipulator: Decoder/Generator/Encoder v1.0
//
// (x) Pluf
//
//////////////////////////////////////////////////////////////

#ifndef __X86IM_H__
#define __X86IM_H__

#if __UNIX__
# define __stdcall 
# define __in 
# define __out 
# define __inout
# define WORD unsigned short
# define DWORD unsigned int
# define BOOL int
# define TRUE 1
# define FALSE 0
#endif

#include "x86im_io.h"
#ifdef __X86IM_USE_FMT__
#include "x86im_fmt.h"
#endif
#include "x86im_gen.h"

#define X86IM_STATUS_SUCCESS                0x0
#define X86IM_STATUS_INVALID_ARGUMENTS      0x1
#define X86IM_STATUS_INVALID_OPCODE         0x2

int __stdcall x86im_dec( __inout x86im_instr_object *io,
                         __in unsigned long mode,
                         __in unsigned char *data );

int __stdcall x86im_gen( __inout x86im_instr_object *io,
                         __in unsigned long options,
                         __in unsigned long code,
                         __in unsigned long reg,
                         __in unsigned long mem,
                         __in unsigned long long disp,
                         __in unsigned long long imm );

int __stdcall x86im_enc( __inout x86im_instr_object *io,
                         __out unsigned char *data );

#endif // __X86IM_H__
