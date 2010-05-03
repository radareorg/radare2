//////////////////////////////////////////////////////////////
//
// x86 Instruction Manipulator: Decoder/Generator/Encoder v1.0
//
// (x) Pluf
//
//////////////////////////////////////////////////////////////

#ifndef __X86IM_FMT_H__
#define __X86IM_FMT_H__

#ifdef __X86IM_USE_FMT__

char *x86f_get_imn( __in x86im_instr_object *io );
char *x86f_get_reg( __in unsigned short reg );
unsigned int x86im_fmt( __in x86im_instr_object *io );

#endif

#endif  // __X86IM_FMT_H__