#undef Elf_
#undef Elf_Vword
#undef ELF_ST_BIND
#undef ELF_ST_TYPE
#undef ELF_ST_INFO
#undef ELF_ST_VISIBILITY
#undef ELF_R_SYM
#undef ELF_R_TYPE
#undef ELF_R_INFO
#undef ELF_M_SYM
#undef ELF_M_SIZE
#undef ELF_M_INFO
	
#ifdef R_BIN_ELF64
# define Elf_(name) Elf64_##name 
# define ELF_ST_BIND       ELF64_ST_BIND
# define ELF_ST_TYPE       ELF64_ST_TYPE
# define ELF_ST_INFO       ELF64_ST_INFO
# define ELF_ST_VISIBILITY ELF64_ST_VISIBILITY
# define ELF_R_SYM         ELF64_R_SYM
# define ELF_R_TYPE        ELF64_R_TYPE
# define ELF_R_INFO        ELF64_R_INFO
# define ELF_M_SYM         ELF64_M_SYM
# define ELF_M_SIZE        ELF64_M_SIZE
# define ELF_M_INFO        ELF64_M_INFO
#else       
# define Elf_(name) Elf32_##name 
# define ELF_ST_BIND       ELF32_ST_BIND
# define ELF_ST_TYPE       ELF32_ST_TYPE
# define ELF_ST_INFO       ELF32_ST_INFO
# define ELF_ST_VISIBILITY ELF32_ST_VISIBILITY
# define ELF_R_SYM         ELF32_R_SYM
# define ELF_R_TYPE        ELF32_R_TYPE
# define ELF_R_INFO        ELF32_R_INFO
# define ELF_M_SYM         ELF32_M_SYM
# define ELF_M_SIZE        ELF32_M_SIZE
# define ELF_M_INFO        ELF32_M_INFO
#endif      

/* MingW doesn't define __BEGIN_DECLS / __END_DECLS. */
#ifndef __BEGIN_DECLS
#  ifdef __cplusplus
#    define __BEGIN_DECLS extern "C" {
#  else
#    define __BEGIN_DECLS
#  endif
#endif
#ifndef __END_DECLS
#  ifdef __cplusplus
#    define __END_DECLS }
#  else
#    define __END_DECLS
#  endif
#endif

#include "glibc_elf.h"

#ifndef _INCLUDE_ELF_SPECS_H
#define _INCLUDE_ELF_SPECS_H

#define ELF_STRING_LENGTH 256

// not strictly ELF, but close enough:
#define        CGCMAG          "\177CGC"
#define        SCGCMAG         4

#define ELFOSABI_HURD          4       /* GNU/HURD */
#define ELFOSABI_86OPEN        5       /* 86open */
#define ELFOSABI_OPENVMS       13      /* OpenVMS  */
#define ELFOSABI_ARM_AEABI     64      /* ARM EABI */

#define EM_BLACKFIN            106             /* Analog Devices Blackfin */
#define EM_MCST_ELBRUS         175
#define EM_PROPELLER           0x5072
#define EM_RISCV               243
#define EM_LANAI               0x8123
#define EM_VIDEOCORE           95 // XXX dupe for EM_NUM
#define EM_VIDEOCORE3          137
#define EM_VIDEOCORE4          200


#endif // _INCLUDE_ELF_SPECS_H
