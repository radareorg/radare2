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
#ifndef __in
#define __in
#endif
#ifndef __out
#define __out
#endif
#ifndef __inout
#define __inout
#endif

char *x86f_get_imn( __in x86im_instr_object *io );
char *x86f_get_reg( __in unsigned short reg );
unsigned int x86im_fmt( __in x86im_instr_object *io );
void x86im_fmt_format_prefix( __in x86im_instr_object *io,
                    __out char *pfx );
void x86im_fmt_format_name( __in x86im_instr_object *io,
                   __in char *name );
void x86im_fmt_format_operand( __in x86im_instr_object *io,
                     __out char *dst,
                     __out char *src );

#endif

#endif  // __X86IM_FMT_H__
