//////////////////////////////////////////////////////////////
//
// x86 Instruction Manipulator: Decoder/Generator/Encoder v1.0
//
// (x) Pluf
//
//////////////////////////////////////////////////////////////

// x86 32/64bit GPI|FPU|MMX|3DN|SSE|SSE2|SSE3

# include <r_types.h>
#if __WINDOWS__
# include <windows.h>
#elif __UNIX__
# include <stdio.h>
#endif

#include "x86im.h"
#include "x86im_itbl.h"

#define X86IM_CORE_OP_DEC                           1
#define X86IM_CORE_OP_GEN                           2

#define X86IM_CORE_OP_IS_DEC(x)                     (x)->op == X86IM_CORE_OP_DEC
#define X86IM_CORE_OP_IS_GEN(x)                     (x)->op == X86IM_CORE_OP_GEN

typedef struct _core_opdata
{
    int op;
    x86im_instr_object *io;
    x86im_itbl_entry *itbl_ent;

    unsigned long options;

    unsigned char *instr;

    unsigned long code;
    unsigned long reg;

    union
    {
		struct
		{
			unsigned long value;
		};

		struct
		{
			unsigned long mode: 16;
			unsigned long base: 4;
			unsigned long index: 4;
			unsigned long scale: 8;
		};

    } mm;

    unsigned long long disp;
    unsigned long long imm;

} core_opdata;

x86im_itbl_entry *x86im_decode_3dnow( __in unsigned char *i,
                                      __in x86im_instr_object *io,
                                      __in core_opdata *opd )
{
    x86im_itbl_entry *itbl_ent;
    unsigned char n, byte_off, id;

    itbl_ent = NULL;

    X86IM_IO_IF_SET_3DNS( io );

    if ( X86IM_CORE_OP_IS_DEC( opd ) )
    {
        byte_off = 2 + 1;

        n = *( i + 2 ) & 0xC7;

        if ( X86IM_IO_IP_HAS_ADSZ( io ) && io->def_adsz == 4 )
        {
            if ( n == 0x6 ||
                 ( ( n & 0xC0 ) == 0x80 ) )
            {
                byte_off += 2;
            }
            else if ( ( n & 0xC0 ) == 0x40 )
            {
                ++byte_off;
            }
        }
        else
        {
            if ( n == 0x5 )
            {
                byte_off += 4;
            }
            else if ( ( n & 0x7 ) == 0x4 )
            {
                ++byte_off;

                if ( n == 0x4 &&
                     ( ( *( i + 3 ) & 0x7 ) == 0x5 ) )
                {
                    byte_off += 4;
                }
            }

            if ( ( n & 0xC0 ) == 0x40 )
            {
                ++byte_off;
            }
            if ( ( n & 0xC0 ) == 0x80 )
            {
                byte_off += 4;
            }
        }

        id = i[ byte_off ];
    }
    else
    {
        id = ( opd->code >> 24 ) & 0xFF;
    }

    X86IM_IO_SET_3DNS( io, id );

    switch( id )
    {
    case 0x0C:    id =  0; break;
    case 0x0D:    id =  1; break;
    case 0x1C:    id =  2; break;
    case 0x1D:    id =  3; break;
    case 0x8A:    id =  4; break;
    case 0x8E:    id =  5; break;
    case 0x90:    id =  6; break;
    case 0x94:    id =  7; break;
    case 0x96:    id =  8; break;
    case 0x97:    id =  9; break;
    case 0x9A:    id = 10; break;
    case 0x9E:    id = 11; break;
    case 0xA0:    id = 12; break;
    case 0xA4:    id = 13; break;
    case 0xA6:    id = 14; break;
    case 0xA7:    id = 15; break;
    case 0xAA:    id = 16; break;
    case 0xAE:    id = 17; break;
    case 0xB0:    id = 18; break;
    case 0xB4:    id = 19; break;
    case 0xB6:    id = 20; break;
    case 0xB7:    id = 21; break;
    case 0xBB:    id = 22; break;
    case 0xBF:    id = 23; break;
    default: id = 0xFF;
    }

    if ( id != 0xFF )
    {
        itbl_ent = &itbl_AMD3DNow[ id ];
    }

    return itbl_ent;
}

void x86im_process_imm_op( __in core_opdata *opd,
                           __in unsigned char *data,
                           __in unsigned int size )
{
    x86im_instr_object *io = opd->io;
    x86im_itbl_entry *itbl_ent = opd->itbl_ent;

    if ( X86IM_CORE_OP_IS_GEN( opd ) )
    {
        data = ( unsigned char * )&opd->imm;
    }

    X86IM_IO_IF_SET( io, X86IM_IO_IF_IMM_OP | X86IM_IO_IF_EXP_OP );

    if ( size == 8 && !ITE_ENC_FIM( itbl_ent ) )
    {
        size >>= 1;
    }

    io->imm_size = size;

    if ( size == X86IM_IO_IM_SZ_BYTE )
    {
        io->imm = *( unsigned char * )data;
    }
    else if ( size == X86IM_IO_IM_SZ_WORD )
    {
        io->imm = *( unsigned short *)data;
    }
    else if ( size <= X86IM_IO_IM_SZ_DWORD )
    {
        io->imm = *( unsigned long * )data;

        if ( size == 3 )
        {
            io->imm &= 0xFFFFFF;
        }
    }
    else
    {
        io->imm = *( unsigned long long *)data;
    }
}

unsigned char x86im_process_reg_op( __in core_opdata *opd,
                                    __in unsigned char rbyte,
                                    __in int grp,
                                    __in int flags,
                                    __in BOOL save )
{
    x86im_instr_object *io = opd->io;
    x86im_itbl_entry *itbl_ent = opd->itbl_ent;
    unsigned long r = 0;

    if ( X86IM_CORE_OP_IS_DEC( opd ) )
    {
        if ( ( flags & ( X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM |
                         X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG ) ) &&
             !X86IM_IO_IF_HAS_MODRM( io ) &&
             save )
        {
            X86IM_IO_IF_SET_MODRM( io );
            io->modrm = rbyte;
        }

        if ( X86IM_IO_ROP_IS_IMP( flags ) ||
             ( flags & ( X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM |
                         X86IM_IO_ROP_LOCATION_SIB_FLD_SBS |
                         X86IM_IO_ROP_LOCATION_OPCODE_OP3 ) ) )
        {
            r = rbyte & 0x7;
        }
        else if ( flags & ( X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG |
                            X86IM_IO_ROP_LOCATION_SIB_FLD_SDX |
                            X86IM_IO_ROP_LOCATION_OPCODE_OPS3 ) )
        {
            r = ( rbyte >> 3 ) & 0x7;
        }
        else if ( flags & X86IM_IO_ROP_LOCATION_OPCODE_OPS2 )
        {
            r = ( rbyte >> 3 ) & 0x3;
        }

        if ( X86IM_IO_IS_MODE_64BIT( io ) && X86IM_IO_IP_HAS_REX( io ) &&
             ( ( flags & X86IM_IO_ROP_EXP ) || ( save == FALSE ) ) )
        {
            if ( grp < X86IM_IO_ROP_GR_MXR )
            {
                if ( flags & ( X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM |
                               X86IM_IO_ROP_LOCATION_SIB_FLD_SBS |
                               X86IM_IO_ROP_LOCATION_OPCODE_OP3 ) )
                {
                    r |= ( ITE_REX_B( itbl_ent ) & X86IM_IO_IP_HAS_REX_B( io ) ) << 3;
                }
                else if ( flags & X86IM_IO_ROP_LOCATION_SIB_FLD_SDX )
                {
                    r |= ( ITE_REX_X( itbl_ent ) & X86IM_IO_IP_HAS_REX_X( io ) ) << 3;
                }
                else if ( flags & X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG )
                {
                    r |= ( ITE_REX_R( itbl_ent ) & X86IM_IO_IP_HAS_REX_R( io ) ) << 3;
                }
            }

            if ( ( grp == X86IM_IO_ROP_SGR_GPR_8 || ( grp == X86IM_IO_ROP_GR_GPR && io->def_opsz == 1 ) ) &&
                 ( !( r & 0x8 ) && ( r > 0x3 ) ) )
            {
                r &= 0x3;

                grp = X86IM_IO_ROP_SGR_GPR_8B;
            }
        }
    }
    else
    {
        if ( ( flags & ( X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM |
                         X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG ) ) &&
             !X86IM_IO_IF_HAS_MODRM( io ) &&
             save )
        {
            X86IM_IO_IF_SET_MODRM( io );
            if ( opd->mm.value == 0 )
            {
                io->modrm |= 0xC0;
            }
            io->modrm |= rbyte;
        }

        if( save && !X86IM_IO_ROP_IS_IMP( flags ) )
        {
            rbyte = ( unsigned char )opd->reg;
        }

        if ( X86IM_IO_ROP_IS_IMP( flags ) ||
             ( flags & ( X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM |
                         X86IM_IO_ROP_LOCATION_SIB_FLD_SBS |
                         X86IM_IO_ROP_LOCATION_OPCODE_OP3 ) ) )
        {
            r = rbyte & 0xF;
        }
        else if ( flags & ( X86IM_IO_ROP_LOCATION_SIB_FLD_SDX |
                            X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG ) )
        {
            r = ( rbyte >> 4 ) & 0xF;
        }
        else if ( flags & X86IM_IO_ROP_LOCATION_OPCODE_OPS2 )
        {
            r = ( opd->code >> 3 ) & 0x3;
        }
        else if ( flags & X86IM_IO_ROP_LOCATION_OPCODE_OPS3 )
        {
            r = ( ( opd->code >> 8 ) >> 3 ) & 0x7;
        }

        if ( flags & X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM )
        {
            io->modrm |= r & 0x7;
        }
        else if ( flags & X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG )
        {
            io->modrm |= ( r & 0x7 ) << 3;
        }
        else if ( flags & X86IM_IO_ROP_LOCATION_SIB_FLD_SBS )
        {
            io->sib |= r & 0x7;
        }
        else if ( flags & X86IM_IO_ROP_LOCATION_SIB_FLD_SDX )
        {
            io->sib |= ( r & 0x7 ) << 3;
        }
        else if ( flags & X86IM_IO_ROP_LOCATION_OPCODE_OP3 )
        {
            io->opcode[0] |= r & 0xF;
        }

        if ( X86IM_IO_IS_MODE_64BIT( io ) && ( r & 0x8 ) )
        {
            if ( flags & ( X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM |
                           X86IM_IO_ROP_LOCATION_SIB_FLD_SBS |
                           X86IM_IO_ROP_LOCATION_OPCODE_OP3 ) )
            {
                io->rexp |= 1;
            }
            else if ( flags & X86IM_IO_ROP_LOCATION_SIB_FLD_SDX )
            {
                io->rexp |= 1 << 1;
            }
            else if ( flags & X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG )
            {
                io->rexp |= 1 << 2;
            }
        }
    }

    if ( grp == X86IM_IO_ROP_GR_GPR )
    {
        r |= ( io->def_opsz << 4 );
    }
    else
    {
        r |= grp;
    }

    if ( save )
    {
        X86IM_IO_IF_SET_REG_OP( io );
        if ( flags & X86IM_IO_ROP_EXP )
        {
            X86IM_IO_IF_SET_EXP_OP( io );
        }
        else
        {
            X86IM_IO_IF_SET_IMP_OP( io );
        }

        r |= flags;

        io->rop[ io->rop_count ] = r;
        ++io->rop_count;
    }

    return ( unsigned char )( r & 0xFF );
}

void x86im_process_mem_disp( __in core_opdata *opd,
                             __in unsigned char *data,
                             __in unsigned int size )
{
    x86im_instr_object *io = opd->io;

    if ( X86IM_CORE_OP_IS_GEN( opd ) )
    {
        data = ( unsigned char * )&opd->disp;
    }

    io->disp_size = size;

    if ( size == X86IM_IO_DP_SZ_BYTE )
    {
        io->disp = *( unsigned char * )data;
    }
    else if ( size == X86IM_IO_DP_SZ_WORD )
    {
        io->disp = *( unsigned short * )data;
    }
    else if ( size == X86IM_IO_DP_SZ_DWORD )
    {
        io->disp = *( unsigned long * )data;
    }
    else
    {
        io->disp = *( unsigned long long * )data;
    }
}

#define M_AUTO_PTR      0x30

void x86im_process_mem_op( __in core_opdata *opd,
                           __in unsigned char *i,
                           __in unsigned int flags,
                           __in unsigned int size )
{
    x86im_instr_object *io = opd->io;
    char mem_reg = 0;
    int n;
    unsigned char modrm_mod,
                  modrm_reg,
                  modrm_rm,
                  sib_scale,
                  sib_index,
                  sib_base;

    X86IM_IO_IF_SET( io, X86IM_IO_IF_MEM_OP|X86IM_IO_IF_EXP_OP );

    io->mem_flags |= flags;

    if ( size != M_AUTO_PTR )
    {
        io->mem_size = size;
    }
    else
    {
        io->mem_size = io->def_opsz;
    }
    if ( flags & X86IM_IO_MOP_MOF )
    {
        x86im_process_mem_disp( opd, i, io->def_adsz );

        io->mem_am |= ( X86IM_IO_MOP_AM16 * ( io->def_adsz >> 1 ) ) |
                       ( X86IM_IO_MOP_AMC_DISP16 * ( io->def_adsz >> 1 ) );
    }
    else
    {
        if ( X86IM_CORE_OP_IS_DEC( opd ) )
        {
            if ( !X86IM_IO_IF_HAS_MODRM( io ) )
            {
                X86IM_IO_IF_SET_MODRM( io );
                io->modrm = i[0];
            }

            n = ( i[0] & 0xC7 );

            modrm_mod  = X86IM_IO_GET_MODRM_FLD_MOD( io->modrm );
            modrm_reg  = X86IM_IO_GET_MODRM_FLD_REG( io->modrm );
            modrm_rm   = X86IM_IO_GET_MODRM_FLD_RM( io->modrm );

            if ( io->def_adsz == 2 )
            {
                X86IM_IO_MOP_SET_AM16( io );

                if ( modrm_mod == 0x1 )
                {
                    x86im_process_mem_disp( opd, i + 1,
                                            X86IM_IO_DP_SZ_BYTE );

                    X86IM_IO_MOP_AMC_SET_DISP8( io );
                }
                else if ( ( modrm_mod == 0x2 ) ||
                          ( modrm_rm == 0x6 ) )
                {
                    x86im_process_mem_disp( opd, i + 1,
                                            X86IM_IO_DP_SZ_WORD );

                    X86IM_IO_MOP_AMC_SET_DISP16( io );
                }

                if ( n != 0x6 )
                {
                    switch ( modrm_rm )
                    {
                    case 0: io->mem_base   = X86IM_IO_ROP_SGR_GPR_16|X86IM_IO_ROP_ID_BX;
                            io->mem_index  = X86IM_IO_ROP_SGR_GPR_16|X86IM_IO_ROP_ID_SI;
                            break;
                    case 1: io->mem_base   = X86IM_IO_ROP_SGR_GPR_16|X86IM_IO_ROP_ID_BX;
                            io->mem_index  = X86IM_IO_ROP_SGR_GPR_16|X86IM_IO_ROP_ID_DI;
                            break;
                    case 2: io->mem_base   = X86IM_IO_ROP_SGR_GPR_16|X86IM_IO_ROP_ID_BP;
                            io->mem_index  = X86IM_IO_ROP_SGR_GPR_16|X86IM_IO_ROP_ID_SI;
                            break;
                    case 3: io->mem_base   = X86IM_IO_ROP_SGR_GPR_16|X86IM_IO_ROP_ID_BP;
                            io->mem_index  = X86IM_IO_ROP_SGR_GPR_16|X86IM_IO_ROP_ID_DI;
                            break;
                    case 4: io->mem_base   = X86IM_IO_ROP_SGR_GPR_16|X86IM_IO_ROP_ID_SI;
                            break;
                    case 5: io->mem_base   = X86IM_IO_ROP_SGR_GPR_16|X86IM_IO_ROP_ID_DI;
                            break;
                    case 6: io->mem_base   = X86IM_IO_ROP_SGR_GPR_16|X86IM_IO_ROP_ID_BP;
                            break;
                    case 7: io->mem_base   = X86IM_IO_ROP_SGR_GPR_16|X86IM_IO_ROP_ID_BX;
                            break;
                    }

                    X86IM_IO_MOP_AMC_SET_BASE( io );
                    if ( modrm_rm <= 3 )
                    {
                        X86IM_IO_MOP_AMC_SET_INDEX( io );
                    }
                }
            }
            else
            {
                if ( io->def_adsz == 4 )
                {
                    mem_reg = X86IM_IO_ROP_SGR_GPR_32;
                    X86IM_IO_MOP_SET_AM32( io );
                }
                else
                {
                    mem_reg = X86IM_IO_ROP_SGR_GPR_64;
                    X86IM_IO_MOP_SET_AM64( io );
                }

                if ( n == 0x4 )
                {
                    X86IM_IO_IF_SET_SIB( io );

                    io->sib = *( char *)( i + 1 );
                }
                else if ( n == 0x5 )
                {
                    x86im_process_mem_disp( opd, i + 1, X86IM_IO_DP_SZ_DWORD );

                    if ( X86IM_IO_IS_MODE_64BIT( io ) )
                    {
                        io->mem_base = X86IM_IO_ROP_ID_RIP;
                        X86IM_IO_MOP_AMC_SET_RIPREL( io );
                    }

                    X86IM_IO_MOP_AMC_SET_DISP32( io );
                }
                else if ( ( n & 0xC0 ) == 0 )
                {
                    io->mem_base = x86im_process_reg_op( opd,
                                                         io->modrm,
                                                         mem_reg,
                                                         X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM,
                                                         FALSE );
                    X86IM_IO_MOP_AMC_SET_BASE( io );
                }
                else if ( ( n & 0x7 ) == 0x4 )
                {
                    x86im_process_mem_disp( opd,
                                            i + 2,
                                            modrm_mod * modrm_mod );

                    X86IM_IO_IF_SET_SIB( io );

                    io->sib = *( char *)( i + 1 );

                    if ( io->disp_size == 1 )
                    {
                        X86IM_IO_MOP_AMC_SET_DISP8( io );
                    }
                    else
                    {
                        X86IM_IO_MOP_AMC_SET_DISP32( io );
                    }
                }
                else
                {
                    x86im_process_mem_disp( opd,
                                            i + 1,
                                            modrm_mod * modrm_mod );

                    io->mem_base = x86im_process_reg_op( opd,
                                                         io->modrm,
                                                         mem_reg,
                                                         X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM,
                                                         FALSE );
                    if ( io->disp_size == 1 )
                    {
                        X86IM_IO_MOP_AMC_SET_DISP8( io );
                    }
                    else
                    {
                        X86IM_IO_MOP_AMC_SET_DISP32( io );
                    }

                    X86IM_IO_MOP_AMC_SET_BASE( io );
                }

                if ( X86IM_IO_IF_HAS_SIB( io ) )
                {
                    sib_scale = X86IM_IO_GET_SIB_FLD_SCALE( io->sib );
                    sib_index = X86IM_IO_GET_SIB_FLD_INDEX( io->sib );
                    sib_base  = X86IM_IO_GET_SIB_FLD_BASE( io->sib );

                    n = x86im_process_reg_op( opd,
                                              io->sib,
                                              mem_reg,
                                              X86IM_IO_ROP_LOCATION_SIB_FLD_SDX,
                                              FALSE );

                    if ( X86IM_IO_ROP_GET_ID( n ) != X86IM_IO_ROP_ID_RSP &&
                         X86IM_IO_ROP_GET_ID( n ) != X86IM_IO_ROP_ID_ESP )
                    {
                        io->mem_index = n;
                        X86IM_IO_MOP_AMC_SET_INDEX( io );

                        io->mem_scale = ( 1 << sib_scale ) & 0xE;
                        if ( io->mem_scale )
                        {
                            X86IM_IO_MOP_AMC_SET_SCALE( io );
                        }
                    }

                    if ( sib_base != 0x5 )
                    {
                        io->mem_base = x86im_process_reg_op( opd,
                                                             io->sib,
                                                             mem_reg,
                                                             X86IM_IO_ROP_LOCATION_SIB_FLD_SBS,
                                                             FALSE );

                        if ( X86IM_IO_ROP_GET_ID( io->mem_base ) == X86IM_IO_ROP_ID_ESP )
                        {
                            io->seg = X86IM_IO_ROP_ID_SS;
                        }

                        X86IM_IO_MOP_AMC_SET_BASE( io );
                    }
                    else
                    {
                        if ( modrm_mod == 0x0 )
                        {
                            x86im_process_mem_disp( opd,
                                                    i + 2,
                                                    4 );

                            X86IM_IO_MOP_AMC_SET_DISP32( io );
                        }
                        else
                        {
                            io->mem_base = x86im_process_reg_op( opd,
                                                                 X86IM_IO_ROP_ID_EBP,
                                                                 mem_reg,
                                                                 X86IM_IO_ROP_LOCATION_SIB_FLD_SBS,
                                                                 FALSE );
                            X86IM_IO_MOP_AMC_SET_BASE( io );
                        }
                    }
                }
            }
        }
        else
        {
            if ( !X86IM_IO_IF_HAS_MODRM( io ) )
            {
                X86IM_IO_IF_SET_MODRM( io );
            }

            if ( io->def_adsz == 4 )
            {
                mem_reg = X86IM_IO_ROP_SGR_GPR_32;
            }
            else
            {
                mem_reg = X86IM_IO_ROP_SGR_GPR_64;
            }

            io->mem_am |= opd->mm.mode & 0x7;

            if ( opd->mm.mode & X86IM_IO_MOP_AMC_SIB )
            {
                X86IM_IO_IF_SET_SIB( io );

                if ( opd->mm.mode & X86IM_IO_MOP_AMC_SIB1 )
                {
                    io->sib = 0x20;
                    X86IM_IO_MOP_AMC_SET_SIB1( io );
                }
                else if ( opd->mm.mode & X86IM_IO_MOP_AMC_SIB2 )
                {
                    io->sib = 0x60;
                    X86IM_IO_MOP_AMC_SET_SIB2( io );
                }
                else if ( opd->mm.mode & X86IM_IO_MOP_AMC_SIB3 )
                {
                    io->sib = 0xA0;
                    X86IM_IO_MOP_AMC_SET_SIB3( io );
                }
                else
                {
                    io->sib = 0xE0;
                    X86IM_IO_MOP_AMC_SET_SIB4( io );
                }
            }

            if ( opd->mm.mode & X86IM_IO_MOP_AMC_SCALE )
            {
                X86IM_IO_IF_SET_SIB( io );
                X86IM_IO_MOP_AMC_SET_SCALE( io );

                io->mem_scale = opd->mm.scale & 0xE;

                io->sib |= ( ( io->mem_scale >> 2 ) + 1 ) << 6;

                if ( ( opd->mm.mode & X86IM_IO_MOP_AMC_SIB ) ||
                     !( opd->mm.mode & X86IM_IO_MOP_AMC_INDEX ) )
                {
                     io->status = X86IM_STATUS_INVALID_ARGUMENTS;
                }
            }

            if ( opd->mm.mode & X86IM_IO_MOP_AMC_INDEX )
            {
                X86IM_IO_IF_SET_SIB( io );
                X86IM_IO_MOP_AMC_SET_INDEX( io );

                io->mem_index = x86im_process_reg_op( opd,
                                                      ( ( opd->mm.value >> 16 ) & 0xFF ),
                                                      mem_reg,
                                                      X86IM_IO_ROP_LOCATION_SIB_FLD_SDX,
                                                      FALSE );

                if ( ( X86IM_IO_ROP_GET_ID( io->mem_index ) == X86IM_IO_ROP_ID_ESP ) ||
                     ( opd->mm.mode & X86IM_IO_MOP_AMC_SIB ) )
                {
                    io->status = X86IM_STATUS_INVALID_ARGUMENTS;
                }
            }

            if ( opd->mm.mode & X86IM_IO_MOP_AMC_BASE )
            {
                X86IM_IO_MOP_AMC_SET_BASE( io );

                if ( X86IM_IO_IF_HAS_SIB( io ) )
                {
                     io->mem_base = x86im_process_reg_op( opd,
                                                          ( ( opd->mm.value >> 16 ) & 0xFF ),
                                                          mem_reg,
                                                          X86IM_IO_ROP_LOCATION_SIB_FLD_SBS,
                                                          FALSE );

                     if ( !( opd->mm.mode & X86IM_IO_MOP_AMC_DISP ) &&
                           ( X86IM_IO_ROP_GET_ID32( io->mem_base ) == X86IM_IO_ROP_ID_EBP ) )
                     {
                        io->status = X86IM_STATUS_INVALID_ARGUMENTS;
                     }
                }
                else
                {
                    io->mem_base = x86im_process_reg_op( opd,
                                                         ( ( opd->mm.value >> 16 ) & 0xFF ),
                                                         mem_reg,
                                                         X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM,
                                                         FALSE );

                    if ( ( X86IM_IO_ROP_GET_ID32( io->mem_base ) == X86IM_IO_ROP_ID_ESP ) ||
                         ( !( opd->mm.mode & X86IM_IO_MOP_AMC_DISP ) && ( X86IM_IO_ROP_GET_ID32( io->mem_base ) == X86IM_IO_ROP_ID_EBP ) ) )
                    {
                        io->status = X86IM_STATUS_INVALID_ARGUMENTS;
                    }
                }
            }

            if ( opd->mm.mode & X86IM_IO_MOP_AMC_DISP8 )
            {
                X86IM_IO_MOP_AMC_SET_DISP8( io );

                x86im_process_mem_disp( opd,
                                        ( unsigned char * )&opd->imm,
                                        X86IM_IO_DP_SZ_BYTE );

                io->modrm |= ( 1 & 0x3 ) << 6;
            }
            else if ( opd->mm.mode & X86IM_IO_MOP_AMC_DISP32 )
            {
                X86IM_IO_MOP_AMC_SET_DISP32( io );

                x86im_process_mem_disp( opd,
                                        ( unsigned char * )&opd->imm,
                                        X86IM_IO_DP_SZ_DWORD );

                if ( !( X86IM_IO_IF_HAS_SIB( io ) ) &&
                     !( opd->mm.mode & X86IM_IO_MOP_AMC_BASE ) )
                {
                    io->modrm |= 0x5;
                }
                else if ( !( opd->mm.mode & X86IM_IO_MOP_AMC_BASE ) &&
                          ( X86IM_IO_IF_HAS_SIB( io ) ) )
                {
                    io->sib |= 0x5;

                    if ( X86IM_IO_IS_MODE_64BIT( io ) )
                    {
                        io->mem_base = X86IM_IO_ROP_ID_RIP;
                        X86IM_IO_MOP_AMC_SET_RIPREL( io );
                    }
                }
                else
                {
                    io->modrm |= 2 << 6;
                }
            }
            else
            {
                io->modrm |= 0 << 6;
            }

            if ( X86IM_IO_IF_HAS_SIB( io ) )
            {
                io->modrm |= 0x4;
            }
        }
    }
}

void x86im_core_process_op( __in core_opdata *opd,
                            __in unsigned short arg,
                            __in unsigned char *i )
{
    x86im_instr_object *io = opd->io;
    x86im_itbl_entry *itbl_ent = opd->itbl_ent;
    unsigned int val = 0;

    if ( ITE_IS_EOP( arg ) )
    {
        if ( ITE_IS_EOP_REG( arg ) )
        {
            switch( arg )
            {
            case ITE_EO_MRRMD:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_GPR,
                                      X86IM_IO_ROP_DST|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM,
                                      TRUE );
                break;

            case ITE_EO_MRRGS:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_GPR,
                                      X86IM_IO_ROP_SRC|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG,
                                      TRUE );
                break;

            case ITE_EO_MRRMS:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_GPR,
                                      X86IM_IO_ROP_SRC|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM,
                                      TRUE );
                break;

            case ITE_EO_MRRGD:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_GPR,
                                      X86IM_IO_ROP_DST|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG,
                                      TRUE );
                break;

            case ITE_EO_MRRMS8:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_SGR_GPR_8,
                                      X86IM_IO_ROP_SRC|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM,
                                      TRUE );
                break;

            case ITE_EO_MRRMD8:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_SGR_GPR_8,
                                      X86IM_IO_ROP_DST|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM,
                                      TRUE );
                break;

            case ITE_EO_MRRMD16:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_SGR_GPR_16,
                                      X86IM_IO_ROP_DST|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM,
                                      TRUE );
                break;

            case ITE_EO_MRRMS16:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_SGR_GPR_16,
                                      X86IM_IO_ROP_SRC|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM,
                                      TRUE );
                break;

            case ITE_EO_MRCX:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_CRG,
                                      ( io->d_bit ? X86IM_IO_ROP_DST: X86IM_IO_ROP_SRC ) | X86IM_IO_ROP_EXP | X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG,
                                      TRUE );
                break;

            case ITE_EO_MRDX:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_DRG,
                                      ( io->d_bit ? X86IM_IO_ROP_DST: X86IM_IO_ROP_SRC ) | X86IM_IO_ROP_EXP | X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG,
                                      TRUE );
                break;

            case ITE_EO_MRSX:

                if ( ( ( i[1] >> 3 ) & 0x7 ) > 5 )
                {
                    io->status = X86IM_STATUS_INVALID_OPCODE;
                }
                else
                {
                    x86im_process_reg_op( opd, i[1],
                                          X86IM_IO_ROP_GR_SRG,
                                          ( io->d_bit ? X86IM_IO_ROP_DST: X86IM_IO_ROP_SRC ) | X86IM_IO_ROP_EXP | X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG,
                                          TRUE );
                }
                break;

            case ITE_EO_ORS2:

                x86im_process_reg_op( opd, i[0],
                                      X86IM_IO_ROP_GR_SRG,
                                      ( itbl_ent->id == X86IM_IO_ID_PUSH_SR1? X86IM_IO_ROP_SRC: X86IM_IO_ROP_DST )|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_OPCODE_OPS2,
                                      TRUE );
                break;

            case ITE_EO_ORS3:

                x86im_process_reg_op( opd, i[0],
                                      X86IM_IO_ROP_GR_SRG,
                                      ( itbl_ent->id == X86IM_IO_ID_PUSH_SR2? X86IM_IO_ROP_SRC: X86IM_IO_ROP_DST )|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_OPCODE_OPS3,
                                      TRUE );
                break;

            case ITE_EO_ORAD:
                x86im_process_reg_op( opd, i[0],
                                      X86IM_IO_ROP_GR_GPR,
                                      X86IM_IO_ROP_DST|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_OPCODE_OP3,
                                      TRUE );
                break;

            case ITE_EO_ORAS:
                x86im_process_reg_op( opd, i[0],
                                      X86IM_IO_ROP_GR_GPR,
                                      X86IM_IO_ROP_SRC|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_OPCODE_OP3,
                                      TRUE );
                break;

            case ITE_EO_MRSTXS:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_STR,
                                      X86IM_IO_ROP_SRC|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM,
                                      TRUE );
                break;

            case ITE_EO_MRSTXD:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_STR,
                                      X86IM_IO_ROP_DST|X86IM_IO_ROP_EXP|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM,
                                      TRUE );
                break;

            case ITE_EO_MRRMMXS:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_MXR,
                                      X86IM_IO_ROP_SRC|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM|X86IM_IO_ROP_EXP,
                                      TRUE );
                break;

            case ITE_EO_MRRMMXD:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_MXR,
                                      X86IM_IO_ROP_DST|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM|X86IM_IO_ROP_EXP,
                                      TRUE );
                break;

            case ITE_EO_MRRGMXS:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_MXR,
                                      X86IM_IO_ROP_SRC|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG|X86IM_IO_ROP_EXP,
                                      TRUE );
                break;

            case ITE_EO_MRRGMXD:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_MXR,
                                      X86IM_IO_ROP_DST|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG|X86IM_IO_ROP_EXP,
                                      TRUE );
                break;

            case ITE_EO_MRRMXMS:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_XMR,
                                      X86IM_IO_ROP_SRC|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM|X86IM_IO_ROP_EXP,
                                      TRUE );
                break;

            case ITE_EO_MRRMXMD:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_XMR,
                                      X86IM_IO_ROP_DST|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM|X86IM_IO_ROP_EXP,
                                      TRUE );
                break;

            case ITE_EO_MRRGXMS:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_XMR,
                                      X86IM_IO_ROP_SRC|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG|X86IM_IO_ROP_EXP,
                                      TRUE );
                break;

            case ITE_EO_MRRGXMD:
                x86im_process_reg_op( opd, i[1],
                                      X86IM_IO_ROP_GR_XMR,
                                      X86IM_IO_ROP_DST|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG|X86IM_IO_ROP_EXP,
                                      TRUE );
                break;
            }
        }
        else if ( ITE_IS_EOP_MEM( arg ) )
        {
            switch( arg )
            {
            case ITE_EO_MMS:
            case ITE_EO_MMD:

                x86im_process_mem_op( opd, i+1,
                                      arg - ITE_EO_MMS + 1,
                                      M_AUTO_PTR );
                break;

            case ITE_EO_MMS8:
            case ITE_EO_MMD8:

                x86im_process_mem_op( opd, i+1,
                                      arg - ITE_EO_MMS8 + 1,
                                      X86IM_IO_MOP_SZ_BYTE_PTR );
                break;

            case ITE_EO_MMS16:
            case ITE_EO_MMD16:

                x86im_process_mem_op( opd, i+1,
                                      arg - ITE_EO_MMS16 + 1,
                                      X86IM_IO_MOP_SZ_WORD_PTR );
                break;

            case ITE_EO_MMS32:
            case ITE_EO_MMD32:

                x86im_process_mem_op( opd, i+1,
                                      arg - ITE_EO_MMS32 + 1,
                                      X86IM_IO_MOP_SZ_DWORD_PTR );
                break;

            case ITE_EO_MMS64:
            case ITE_EO_MMD64:

                x86im_process_mem_op( opd, i+1,
                                      arg - ITE_EO_MMS64 + 1,
                                      X86IM_IO_MOP_SZ_QWORD_PTR );
                break;

            case ITE_EO_MMS80:
            case ITE_EO_MMD80:

                x86im_process_mem_op( opd, i+1,
                                      arg - ITE_EO_MMS80 + 1,
                                      X86IM_IO_MOP_SZ_TBYTE_PTR );
                break;

            case ITE_EO_MMS128:
            case ITE_EO_MMD128:

                x86im_process_mem_op( opd, i+1,
                                      arg - ITE_EO_MMS128 + 1,
                                      X86IM_IO_MOP_SZ_OWORD_PTR );
                break;

            case ITE_EO_MMDTRS:
            case ITE_EO_MMDTRD:

                x86im_process_mem_op( opd, i+1,
                                      arg - ITE_EO_MMDTRS + 1,
                                      M_AUTO_PTR );

                if ( io->def_opsz == 2 )
                {
                    --io->mem_size;
                }

                io->mem_size += 2;

                break;

            case ITE_EO_MMFP:

                x86im_process_mem_op( opd, i+1,
                                      X86IM_IO_MOP_SRC,
                                      M_AUTO_PTR );
                io->mem_size += 2;

                break;

            case ITE_EO_FPU_ST:

                if ( itbl_ent->id == X86IM_IO_ID_FRSTOR )
                {
                    val = X86IM_IO_MOP_SRC;
                }
                else
                {
                    val = X86IM_IO_MOP_DST;
                }

                x86im_process_mem_op( opd, i+1,
                                      val,
                                      io->def_opsz == 2? X86IM_IO_MOP_SZ_FPUSTA_PTR: X86IM_IO_MOP_SZ_FPUSTB_PTR );
                break;

            case ITE_EO_FPU_ENV:

                if ( itbl_ent->id == X86IM_IO_ID_FLDENV )
                {
                    val = X86IM_IO_MOP_SRC;
                }
                else
                {
                    val = X86IM_IO_MOP_DST;
                }

                x86im_process_mem_op( opd, i+1,
                                      val,
                                      io->def_opsz == 2? X86IM_IO_MOP_SZ_FPUENVA_PTR: X86IM_IO_MOP_SZ_FPUENVB_PTR );
                break;

            case ITE_EO_FPU_XST:

                if ( itbl_ent->id == X86IM_IO_ID_FXRSTOR )
                {
                    val = X86IM_IO_MOP_SRC;
                }
                else
                {
                    val = X86IM_IO_MOP_DST;
                }

                x86im_process_mem_op( opd, i+1,
                                      val,
                                      X86IM_IO_MOP_SZ_FXST_PTR );
                break;

            case ITE_EO_BNDMMS:

                x86im_process_mem_op( opd, i+1,
                                      X86IM_IO_MOP_SRC,
                                      io->def_opsz == 2? X86IM_IO_MOP_SZ_DWORD_PTR: X86IM_IO_MOP_SZ_QWORD_PTR );
                break;

            case ITE_EO_MMFD:

                x86im_process_mem_op( opd, i+1,
                                      X86IM_IO_MOP_MOF | ( io->d_bit ? X86IM_IO_MOP_DST: X86IM_IO_MOP_SRC ),
                                      M_AUTO_PTR );
                break;
            }
        }
        else if ( ITE_IS_EOP_RM( arg ) )
        {
            switch( arg )
            {

            case ITE_EO_SRGMM:
            case ITE_EO_SRGMM8:
            case ITE_EO_SRG8MM8:
            case ITE_EO_SRGMM16:
            case ITE_EO_SRG16MM16:

                if ( X86IM_CORE_OP_IS_DEC( opd ) )
                {
                    val = ( i[1] >> 6 ) ^ 0x3;
                }
                else
                {
                    val = opd->mm.value;
                }

                if ( val == 0 )
                {
                    if ( arg == ITE_EO_SRG8MM8 )
                    {
                        arg = X86IM_IO_ROP_SGR_GPR_8;
                    }
                    else if ( arg == ITE_EO_SRG16MM16 )
                    {
                        arg = X86IM_IO_ROP_SGR_GPR_16;
                    }
                    else
                    {
                        arg = X86IM_IO_ROP_GR_GPR;
                    }
                    x86im_process_reg_op( opd, i[1],
                                          arg,
                                          X86IM_IO_ROP_SRC|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM|X86IM_IO_ROP_EXP,
                                          TRUE );
                    ++io->id;
                }
                else
                {
                    if ( arg == ITE_EO_SRGMM )
                    {
                        arg = M_AUTO_PTR;
                    }
                    else if ( ( arg == ITE_EO_SRGMM8 ) ||
                              ( arg == ITE_EO_SRG8MM8 ) )
                    {
                        arg = X86IM_IO_MOP_SZ_BYTE_PTR;
                    }
                    else
                    {
                        arg = X86IM_IO_MOP_SZ_WORD_PTR;
                    }

                    x86im_process_mem_op( opd, i+1, X86IM_IO_MOP_SRC, arg );
                }
                break;

            case ITE_EO_DRGMM:
            case ITE_EO_DRGMM16:
            case ITE_EO_DRG16MM16:

                if ( X86IM_CORE_OP_IS_DEC( opd ) )
                {
                    val = ( i[1] >> 6 ) ^ 0x3;
                }
                else
                {
                    val = opd->mm.value;
                }

                if ( val == 0 )
                {
                    if ( arg == ITE_EO_DRG16MM16 )
                    {
                        arg = X86IM_IO_ROP_SGR_GPR_16;
                    }
                    else
                    {
                        arg = X86IM_IO_ROP_GR_GPR;
                    }
                    x86im_process_reg_op( opd, i[1],
                                          arg,
                                          X86IM_IO_ROP_DST|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM|X86IM_IO_ROP_EXP,
                                          TRUE );
                    ++io->id;
                }
                else
                {
                    x86im_process_mem_op( opd, i+1, X86IM_IO_MOP_DST,
                                          arg == ITE_EO_DRGMM ? M_AUTO_PTR:
                                                                X86IM_IO_MOP_SZ_WORD_PTR );
                }
                break;

            case ITE_EO_MXSRGMM:
            case ITE_EO_MXSRGMM32:

                if ( X86IM_CORE_OP_IS_DEC( opd ) )
                {
                    val = ( i[1] >> 6 ) ^ 0x3;
                }
                else
                {
                    val = opd->mm.value;
                }

                if ( val == 0 )
                {
                    x86im_process_reg_op( opd, i[1],
                                          X86IM_IO_ROP_GR_MXR,
                                          X86IM_IO_ROP_SRC|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM|X86IM_IO_ROP_EXP,
                                          TRUE );
                }
                else
                {
                    x86im_process_mem_op( opd, i+1, X86IM_IO_MOP_SRC,
                                          arg == ITE_EO_MXSRGMM ? X86IM_IO_MOP_SZ_QWORD_PTR:
                                                                  X86IM_IO_MOP_SZ_DWORD_PTR );
                    ++io->id;
                }
                break;

            case ITE_EO_MXDRGMM:

                if ( X86IM_CORE_OP_IS_DEC( opd ) )
                {
                    val = ( i[1] >> 6 ) ^ 0x3;
                }
                else
                {
                    val = opd->mm.value;
                }

                if ( val == 0 )
                {
                    x86im_process_reg_op( opd, i[1],
                                          X86IM_IO_ROP_GR_MXR,
                                          X86IM_IO_ROP_DST|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM|X86IM_IO_ROP_EXP,
                                          TRUE );
                }
                else
                {
                    x86im_process_mem_op( opd, i+1, X86IM_IO_MOP_DST, X86IM_IO_MOP_SZ_QWORD_PTR );
                    ++io->id;
                }
                break;

            case ITE_EO_XMSRGMM:
            case ITE_EO_XMSRGMM32:
            case ITE_EO_XMSRGMM64:

                if ( X86IM_CORE_OP_IS_DEC( opd ) )
                {
                    val = ( i[1] >> 6 ) ^ 0x3;
                }
                else
                {
                    val = opd->mm.value;
                }

                if ( val == 0 )
                {
                    x86im_process_reg_op( opd, i[1],
                                          X86IM_IO_ROP_GR_XMR,
                                          X86IM_IO_ROP_SRC|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM|X86IM_IO_ROP_EXP,
                                          TRUE );
                }
                else
                {
                    if ( arg == ITE_EO_XMSRGMM )
                    {
                        arg = X86IM_IO_MOP_SZ_OWORD_PTR;
                    }
                    else if ( arg == ITE_EO_XMSRGMM64 )
                    {
                        arg = X86IM_IO_MOP_SZ_QWORD_PTR;
                    }
                    else
                    {
                        arg = X86IM_IO_MOP_SZ_DWORD_PTR;
                    }

                    x86im_process_mem_op( opd, i+1, X86IM_IO_MOP_SRC, arg );

                    ++io->id;
                }
                break;

            case ITE_EO_XMDRGMM:
            case ITE_EO_XMDRGMM32:
            case ITE_EO_XMDRGMM64:

                if ( X86IM_CORE_OP_IS_DEC( opd ) )
                {
                    val = ( i[1] >> 6 ) ^ 0x3;
                }
                else
                {
                    val = opd->mm.value;
                }

                if ( val == 0 )
                {
                    x86im_process_reg_op( opd, i[1],
                                          X86IM_IO_ROP_GR_XMR,
                                          X86IM_IO_ROP_DST|X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM|X86IM_IO_ROP_EXP,
                                          TRUE );
                }
                else
                {
                    if ( arg == ITE_EO_XMDRGMM )
                    {
                        arg = X86IM_IO_MOP_SZ_OWORD_PTR;
                    }
                    else if ( arg == ITE_EO_XMDRGMM64 )
                    {
                        arg = X86IM_IO_MOP_SZ_QWORD_PTR;
                    }
                    else
                    {
                        arg = X86IM_IO_MOP_SZ_DWORD_PTR;
                    }

                    x86im_process_mem_op( opd, i+1, X86IM_IO_MOP_DST, arg );

                    ++io->id;
                }
                break;
            }
        }
        else if ( ITE_IS_EOP_IMM( arg ) )
        {
            switch( arg )
            {
            case ITE_EO_IMMO:

                x86im_process_imm_op( opd,
                                      i + 1,
                                      io->s_bit ? 1: io->def_opsz );
                break;

            case ITE_EO_IMMO8:
            case ITE_EO_IMMO16:
            case ITE_EO_IMMO32:

                x86im_process_imm_op( opd,
                                      i + 1,
                                      ( arg - ITE_EO_IMMO8 ) + 1 );
                break;

            case ITE_EO_IMM2O24:

                x86im_process_imm_op( opd,
                                      i + 1,
                                      3 );
                break;

            case ITE_EO_IMMR:
            case ITE_EO_IMMR8:

                if ( arg == ITE_EO_IMMR8 || io->s_bit )
                {
                    arg = 1;
                }
                else
                {
                    arg = io->def_opsz;
                }

                x86im_process_imm_op( opd,
                                      i + 2,
                                      arg );
                break;

            case ITE_EO_IMMM:
            case ITE_EO_IMMM8:

                if ( arg == ITE_EO_IMMM8 || io->s_bit )
                {
                    arg = 1;
                }
                else
                {
                    arg = io->def_opsz;
                }

                x86im_process_imm_op( opd,
                                      i +
                                      1 +
                                      1 +
                                      X86IM_IO_IF_HAS_SIB( io ) +
                                      io->disp_size,
                                      arg );
                break;

            case ITE_EO_IMMRGMM:
            case ITE_EO_IMMRGMM8:

                if ( X86IM_CORE_OP_IS_DEC( opd ) )
                {
                    val = ( i[1] >> 6 ) ^ 0x3;
                }
                else
                {
                    val = opd->mm.value;
                }

                if ( arg == ITE_EO_IMMRGMM8 || io->s_bit )
                {
                    arg = 1;
                }
                else
                {
                    arg = io->def_opsz;
                }

                if ( val == 0 )
                {
                    x86im_process_imm_op( opd,
                                          i + 2,
                                          arg );
                }
                else
                {
                    x86im_process_imm_op( opd,
                                          i +
                                          1 +
                                          1 +
                                          X86IM_IO_IF_HAS_SIB( io ) +
                                          io->disp_size,
                                          arg );
                }

                break;

            case ITE_EO_IMMSL:

                X86IM_IO_IF_SET_SEL( io );

                if ( X86IM_CORE_OP_IS_DEC( opd ) )
                {
                    io->selector = *( unsigned short * )( i + 1 + io->imm_size );
                }
                else
                {
                    io->selector = ( unsigned short )opd->disp;
                }

                io->len += 2;

                break;
            }
        }
        else
        {
            switch( arg )
            {
            case ITE_EO_SOTTTN:

                if ( X86IM_CORE_OP_IS_DEC( opd ) )
                {
                    io->tttn_fld  = ( char )*i & 0xF;
                }
                else
                {
                    io->tttn_fld = ( opd->reg >> 8 ) & 0xF;
                    io->opcode[ itbl_ent->len - 1 ] |= io->tttn_fld;
                }
                X86IM_IO_IF_SET_TTTN( io );
                break;

            case ITE_EO_ARPLOP1:

                if ( X86IM_CORE_OP_IS_DEC( opd ) )
                {
                    val = ( i[1] >> 6 ) ^ 0x3;
                }
                else
                {
                    val = opd->mm.value;
                }

                if ( val == 0 || X86IM_IO_IS_MODE_64BIT( io ) )
                {
                    x86im_process_reg_op( opd, i[1],
                                          X86IM_IO_IS_MODE_64BIT( io )? X86IM_IO_ROP_GR_GPR:
                                                                        X86IM_IO_ROP_SGR_GPR_16,
                                          X86IM_IO_ROP_DST|X86IM_IO_ROP_EXP|( X86IM_IO_IS_MODE_64BIT( io )? X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG:
                                                                                                            X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM ),
                                          TRUE );
                }
                else
                {
                    x86im_process_mem_op( opd, i + 1, X86IM_IO_MOP_DST, X86IM_IO_MOP_SZ_WORD_PTR );
                }

                break;

            case ITE_EO_ARPLOP2:

                if ( X86IM_CORE_OP_IS_DEC( opd ) )
                {
                    val = ( i[1] >> 6 ) ^ 0x3;
                }
                else
                {
                    val = opd->mm.value;
                }

                if ( val == 0 || X86IM_IO_IS_MODE_32BIT( io ) )
                {
                    x86im_process_reg_op( opd, i[1],
                                          X86IM_IO_IS_MODE_64BIT( io )? X86IM_IO_ROP_SGR_GPR_32:
                                                                        X86IM_IO_ROP_SGR_GPR_16,
                                          X86IM_IO_ROP_SRC|X86IM_IO_ROP_EXP|( X86IM_IO_IS_MODE_64BIT( io )? X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM:
                                                                                                            X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG ),
                                          TRUE );
                }
                else
                {
                    x86im_process_mem_op( opd, i + 1, X86IM_IO_MOP_SRC, X86IM_IO_MOP_SZ_DWORD_PTR );
                }

                break;

            case ITE_EO_CMPXCHG:

                x86im_process_mem_op( opd, i + 1,
                                      X86IM_IO_MOP_SOD,
                                      io->def_opsz == 8 ? X86IM_IO_MOP_SZ_OWORD_PTR:
                                                          X86IM_IO_MOP_SZ_QWORD_PTR );
                break;
            }
        }
    }
    else
    {
        switch( arg )
        {
        case ITE_IO_IRAS:
        case ITE_IO_IRAD:
            x86im_process_reg_op( opd,
                                  X86IM_IO_ROP_ID_EAX,
                                  X86IM_IO_ROP_GR_GPR,
                                  ( arg - ITE_IO_IRAS ? X86IM_IO_ROP_DST: X86IM_IO_ROP_SRC)|X86IM_IO_ROP_IMP,
                                  TRUE );
            break;

        case ITE_IO_MRST0S:
        case ITE_IO_MRST0D:
            x86im_process_reg_op( opd,
                                  X86IM_IO_ROP_ID_ST0,
                                  X86IM_IO_ROP_GR_STR,
                                  ( arg - ITE_IO_MRST0S ? X86IM_IO_ROP_DST: X86IM_IO_ROP_SRC )|X86IM_IO_ROP_IMP,
                                  TRUE );
            break;

        case ITE_IO_RC8S:
            x86im_process_reg_op( opd,
                                  X86IM_IO_ROP_ID_CL,
                                  X86IM_IO_ROP_SGR_GPR_8,
                                  X86IM_IO_ROP_SRC|X86IM_IO_ROP_IMP,
                                  TRUE );
            break;

        case ITE_IO_RD16S:
            x86im_process_reg_op( opd,
                                  X86IM_IO_ROP_ID_DX,
                                  X86IM_IO_ROP_SGR_GPR_16,
                                  X86IM_IO_ROP_SRC|X86IM_IO_ROP_IMP,
                                  TRUE );
            break;

        case ITE_IO_IMM1:
                X86IM_IO_IF_SET( io, X86IM_IO_IF_IMM_OP|X86IM_IO_IF_EXP_OP );
                io->imm        = 1;
                io->imm_size   = 1;
                io->len--;

                break;
        }
    }
}

x86im_itbl_entry *x86im_search_cmd( __in unsigned char *i,
                                    __in core_opdata *opd,
                                    __in x86im_instr_object *io )
{
    x86im_itbl_entry *itbl_ent, **table;
    unsigned char mask, index, prefix,
                  modrm,
                  rm, mod, reg,
                  grp;

    grp = index = prefix = mask = modrm = 0;

    io->opcode[0] = *i;

    itbl_ent = &itbl_grp_invalid[0];

    if ( io->opcode[0] == 0x0F )
    {
        index = io->opcode[1] = *( i + 1 );

        prefix = io->prefix & 0xE;

        table = NULL;

        if ( index == 0x38 )
        {
            index = io->opcode[2] = *( i + 2 );

            if ( !( prefix & ( X86IM_IO_IP_F2|X86IM_IO_IP_F3 ) ) &&
                 index < 0x20 )
            {
                table = itbl_3byte_38;
            }

            modrm = *( i + 3 );
        }
        else if ( index == 0x3A )
        {
            index = io->opcode[2] = *( i + 2 );

            if ( !( prefix & ( X86IM_IO_IP_F2|X86IM_IO_IP_F3 ) ) &&
                 index < 0x10 )
            {
                table = itbl_3byte_3A;
            }

            modrm = *( i + 3 );
        }
        else if ( index == 0x0F )
        {
            itbl_ent = x86im_decode_3dnow( i, io, opd );
        }
        else
        {
            modrm = *( i + 2 );

            table = itbl_2byte;;
        }

        if ( table )
        {
            itbl_ent = &table[ 3 ][ index ];

            if ( itbl_ent->id == X86IM_GRP )
            {
                mod = X86IM_IO_GET_MODRM_FLD_MOD( modrm );
                reg = X86IM_IO_GET_MODRM_FLD_REG( modrm );
                rm = X86IM_IO_GET_MODRM_FLD_RM( modrm );

                grp = ( unsigned char )itbl_ent->grp;

                itbl_ent = &itbl_2byte_grps[ grp + 3 ][ reg ];

                if ( ITE_IS_SOMI( itbl_ent ) )
                {
                    table = itbl_2byte_grps;
                    index = reg;
                }
                else if ( ( index == 0xAE ) &&
                          ( mod == 0x3 ) )
                {
                    itbl_ent = &itbl_grp15_op_0F_AE_rm[ reg ];
                }
                else if ( ( index == 0x1 ) &&
                          ( mod == 0x3 ) )
                {
                    if ( reg == 1 )
                    {
                        itbl_ent = &itbl_grp7_op_0F_01_reg1[ rm ];
                    }
                    else if ( reg == 7 )
                    {
                        itbl_ent = &itbl_grp7_op_0F_01_reg7[ rm ];
                    }
                    else if ( reg != 4 && reg != 6 )
                    {
                        itbl_ent = &itbl_grp_invalid[0];
                    }
                }
            }

            if ( ITE_IS_SOMI( itbl_ent ) )
            {
                X86IM_IO_IF_SET_SOMI( io );

                if ( prefix )
                {
                    if ( prefix < 9 && prefix != 6 )
                    {
                        X86IM_IO_IF_SET_MP( io );

                        io->somimp = prefix;

                        prefix >>= 2;

                        itbl_ent = &table[ prefix + grp ][ index ];
                    }
                    else
                    {
                        itbl_ent = &itbl_grp_invalid[0];
                    }
                }
            }

            if ( X86IM_CORE_OP_IS_GEN( opd ) )
            {
                if ( itbl_ent )
                {
                    if ( itbl_ent->id != ITE_INV )
                    {
                        if ( ( opd->options & X86IM_GEN_OAT_NON_PACKED ) &&
                             !( opd->options & X86IM_GEN_OAT_BYTE ) &&
                             ITE_BIT_WB( itbl_ent ) )
                        {
                            if ( ( index != 0xBF ) && ( index != 0xB7 ) )
                            {
                                ++itbl_ent;
                                mask |= 0x1;
                            }
                        }
                        else if ( ( opd->options & X86IM_GEN_OAT_PACKED ) &&
                                  ( opd->options & ( X86IM_GEN_OAT_BYTE|
                                                     X86IM_GEN_OAT_WORD|
                                                     X86IM_GEN_OAT_DWORD|
                                                     X86IM_GEN_OAT_QWORD ) ) &&
                                  ITE_BIT_GG( itbl_ent ) )
                        {
                            itbl_ent += X86IM_GEN_OAT_GET_PO_SIZE( opd );
                            mask |= X86IM_GEN_OAT_GET_PO_SIZE( opd );
                        }

                        *( i + ( itbl_ent->len - 1 ) ) |= mask;
                        io->opcode[ itbl_ent->len - 1 ] |= mask;
                    }
                }
            }
        }
    }
    else
    {
        index = io->opcode[0];
        modrm = *( i + 1 );

        if ( ( 0xF8 & index ) == 0xD8 )
        {
            if ( modrm <= 0xBF )
            {
                reg = X86IM_IO_GET_MODRM_FLD_REG( modrm );

                itbl_ent = &cmd_fpu_tbl_00_BF[ index & 0x7 ][ reg ];
            }
            else
            {
                itbl_ent = &cmd_fpu_tbl_C0_FF[ index & 0x7 ][ modrm - 0xC0 ];
            }
        }
        else
        {
            itbl_ent = &itbl_1byte[ index ];

            if ( X86IM_CORE_OP_IS_GEN( opd ) )
            {
                if ( ( opd->options & X86IM_GEN_OAT_SIGN ) &&
                     ITE_BIT_SB( itbl_ent ) )
                {
                    if ( itbl_ent->id == X86IM_GRP )
                    {
                        grp += 2;
                    }
                    else
                    {
                        itbl_ent += 2;
                    }

                    mask |= 0x1 << 1;
                }
                if ( ( opd->options & X86IM_GEN_OAT_NON_PACKED ) &&
                     !( opd->options & X86IM_GEN_OAT_BYTE ) &&
                     ITE_BIT_WX( itbl_ent ) )
                {
                    if ( itbl_ent->id == X86IM_GRP )
                    {
                        ++grp;
                    }
                    else
                    {
                        ++itbl_ent;
                    }

                    if ( ( io->opcode[0] & 0xF0 ) == 0xB0 )
                    {
                        mask |= 0x1 << 3;
                    }
                    else
                    {
                        mask |= 0x1;
                    }
                }

                *i |= mask;
                io->opcode[0] |= mask;
            }

            if ( itbl_ent->id == X86IM_GRP )
            {
                reg = X86IM_IO_GET_MODRM_FLD_REG( modrm );

                itbl_ent = &itbl_1byte_grps[ itbl_ent->grp + grp ][ reg ];
            }
        }
    }

    if ( X86IM_CORE_OP_IS_GEN( opd ) )
    {
        io->modrm = modrm;
    }

    if ( itbl_ent )
    {
        if ( ( itbl_ent->id == ITE_INV ) ||
             ( X86IM_IO_IS_MODE_64BIT( io ) && ITE_ENC_I64( itbl_ent ) ) ||
             ( X86IM_IO_IS_MODE_32BIT( io ) && ITE_ENC_O64( itbl_ent ) ) ||
             ( ITE_ENC_MO( itbl_ent ) && ITE_ENC_ISM( modrm, itbl_ent ) ) )
        {
            io->status = X86IM_STATUS_INVALID_OPCODE;
            return NULL;
        }
    }

    return itbl_ent;
}

int x86im_core( __in int core_op,
                __in core_opdata *opd )
{
    x86im_instr_object *io;
    x86im_itbl_entry *itbl_ent;
    unsigned char *i, val;
    unsigned long a;
    unsigned short op;

    opd->op = core_op;

    io = opd->io;

    io->status = X86IM_STATUS_SUCCESS;

    for ( a = 0; a < sizeof( x86im_instr_object ); a++ )
    {
        *( char * )( ( char * )io + a ) = 0x0;
    }

    X86IM_IO_SET_MODE( io, opd->options );

    io->def_opsz = 4;
    io->def_adsz = 4;

    if ( X86IM_IO_IS_MODE_64BIT( io ) )
    {
        io->def_adsz <<= 1;
    }

    io->seg = X86IM_IO_ROP_ID_DS;

    if ( X86IM_CORE_OP_IS_DEC( opd ) )
    {
        i = opd->instr;

        for ( a = 0; a < 4; a++ )
        {
            val = *i;

            if ( ( val == X86IM_IO_IP_VALUE_LOCK ) &&
                 !X86IM_IO_IP_HAS_LOCK( io ) )
            {
                X86IM_IO_IP_SET_LOCK( io );
                X86IM_IO_IP_SET_LOCK_POS( io, a );
                io->prefix_values[ a ] = X86IM_IO_IP_VALUE_LOCK;
                ++io->prefix_count;
            }
            else if ( ( ( 0xFE & val ) == 0xF2 ) &&
                       !( X86IM_IO_IP_HAS( io, X86IM_IO_IP_REPE|X86IM_IO_IP_REPN ) ) )
            {
                if ( val == 0xF3 )
                {
                    X86IM_IO_IP_SET_REPE( io );
                }
                else
                {
                    X86IM_IO_IP_SET_REPN( io );
                }
                X86IM_IO_IP_SET_REP_POS( io, a );
                io->prefix_values[ a ] = val;
                ++io->prefix_count;
            }
            else if ( ( val == X86IM_IO_IP_VALUE_OPSZ ) &&
                      !X86IM_IO_IP_HAS_OPSZ( io ) )
            {
                X86IM_IO_IP_SET_OPSZ( io );
                X86IM_IO_IP_SET_OPSZ_POS( io, a );
                io->prefix_values[ a ] = X86IM_IO_IP_VALUE_OPSZ;
                ++io->prefix_count;
            }
            else if ( ( val == X86IM_IO_IP_VALUE_ADSZ ) &&
                      !X86IM_IO_IP_HAS_ADSZ( io ) )
            {
                X86IM_IO_IP_SET_ADSZ( io );
                X86IM_IO_IP_SET_ADSZ_POS( io, a );
                io->prefix_values[ a ] = X86IM_IO_IP_VALUE_ADSZ;
                ++io->prefix_count;
            }
            else if ( ( ( ( 0xEF & val ) == 0x26 ) ||
                        ( ( 0xEF & val ) == 0x2E ) ||
                        ( ( 0xFE & val ) == 0x64 ) ) &&
                      ( !X86IM_IO_IP_HAS_SGXS( io ) ) )
            {
                switch( val )
                {
                case 0x26:  io->seg = X86IM_IO_ROP_ID_ES;
                            X86IM_IO_IP_SET_SGES( io );
                            break;
                case 0x36:  io->seg = X86IM_IO_ROP_ID_SS;
                            X86IM_IO_IP_SET_SGSS( io );
                            break;
                case 0x2E:  io->seg = X86IM_IO_ROP_ID_CS;
                            X86IM_IO_IP_SET_SGCS( io );
                            break;
                case 0x3E:  io->seg = X86IM_IO_ROP_ID_DS;
                            X86IM_IO_IP_SET_SGDS( io );
                            break;
                case 0x64:  io->seg = X86IM_IO_ROP_ID_FS;
                            X86IM_IO_IP_SET_SGFS( io );
                            break;
                case 0x65:  io->seg = X86IM_IO_ROP_ID_GS;
                            X86IM_IO_IP_SET_SGGS( io );
                            break;
                }
                X86IM_IO_IF_SET_SGP( io );
                X86IM_IO_IP_SET_SGXS_POS( io, a );
                io->prefix_values[ a ] = val;
                ++io->prefix_count;
            }
            else
            {
                break;
            }

            X86IM_IO_IF_SET_PFX( io );

            ++i;
        }

        if ( X86IM_IO_IS_MODE_64BIT( io ) &&
             ( ( *i & 0xF0 ) == 0x40 ) )
        {
            io->rexp = *i;
            X86IM_IO_IF_SET_PFX( io );
            X86IM_IO_IP_SET_REX( io );
            ++io->prefix_count;
            ++i;
        }
    }
    else
    {
        for ( a = 0; a < 4; a++ )
        {
            if ( ( opd->options & X86IM_IO_IP_LOCK ) &&
                 !X86IM_IO_IP_HAS_LOCK( io ) )
            {
                X86IM_IO_IP_SET_LOCK( io );
                X86IM_IO_IP_SET_LOCK_POS( io, a );
                io->prefix_values[ a ] = X86IM_IO_IP_VALUE_LOCK;
                ++io->prefix_count;
            }
            else if ( ( opd->options & ( X86IM_IO_IP_REPE|X86IM_IO_IP_REPN ) ) &&
                      !( X86IM_IO_IP_HAS( io, X86IM_IO_IP_REPE|X86IM_IO_IP_REPN ) ) )
            {
                if ( opd->options & X86IM_IO_IP_REPE )
                {
                    X86IM_IO_IP_SET_REPE( io );
                    io->prefix_values[ a ] = X86IM_IO_IP_VALUE_REPE;
                }
                else
                {
                    X86IM_IO_IP_SET_REPN( io );
                    io->prefix_values[ a ] = X86IM_IO_IP_VALUE_REPN;
                }
                X86IM_IO_IP_SET_REP_POS( io, a );
                ++io->prefix_count;
            }
            else if ( ( ( ( opd->mm.mode & X86IM_IO_MOP_AM16 ) && X86IM_IO_IS_MODE_32BIT( io ) ) ||
                        ( ( opd->mm.mode & X86IM_IO_MOP_AM32 ) && X86IM_IO_IS_MODE_64BIT( io ) ) ||
                      ( opd->options & X86IM_IO_IP_ADSZ ) ) && !X86IM_IO_IP_HAS_ADSZ( io ) )
            {
                X86IM_IO_IP_SET_ADSZ( io );
                X86IM_IO_IP_SET_OPSZ_POS( io, a );
                io->prefix_values[ a ] = X86IM_IO_IP_VALUE_ADSZ;
                ++io->prefix_count;
            }
            else if ( ( ( ( opd->options & X86IM_GEN_OAT_NON_PACKED ) &&
                          ( opd->options & X86IM_GEN_OAT_WORD ) ) ||
                        ( opd->options & X86IM_IO_IP_OPSZ ) ) &&
                      !X86IM_IO_IP_HAS_OPSZ( io ) )
            {
                X86IM_IO_IP_SET_OPSZ( io );
                X86IM_IO_IP_SET_OPSZ_POS( io, a );
                io->prefix_values[ a ] = X86IM_IO_IP_VALUE_OPSZ;
                ++io->prefix_count;
            }
            else if ( ( opd->options & X86IM_IO_IP_SGXS ) &&
                      !X86IM_IO_IP_HAS_SGXS( io ) )
            {
                if ( opd->options & X86IM_IO_IP_SGES )
                {
                    io->seg = X86IM_IO_ROP_ID_ES;
                    X86IM_IO_IP_SET_SGES( io );
                    io->prefix_values[ a ] = X86IM_IO_IP_VALUE_SGES;
                }
                else if ( opd->options & X86IM_IO_IP_SGSS )
                {
                    io->seg = X86IM_IO_ROP_ID_SS;
                    X86IM_IO_IP_SET_SGSS( io );
                    io->prefix_values[ a ] = X86IM_IO_IP_VALUE_SGSS;
                }
                else if ( opd->options & X86IM_IO_IP_SGCS )
                {
                    io->seg = X86IM_IO_ROP_ID_CS;
                    X86IM_IO_IP_SET_SGCS( io );
                    io->prefix_values[ a ] = X86IM_IO_IP_VALUE_SGCS;
                }
                else if ( opd->options & X86IM_IO_IP_SGDS )
                {
                    io->seg = X86IM_IO_ROP_ID_DS;
                    X86IM_IO_IP_SET_SGDS( io );
                    io->prefix_values[ a ] = X86IM_IO_IP_VALUE_SGDS;
                }
                else if ( opd->options & X86IM_IO_IP_SGFS )
                {
                    io->seg = X86IM_IO_ROP_ID_FS;
                    X86IM_IO_IP_SET_SGFS( io );
                    io->prefix_values[ a ] = X86IM_IO_IP_VALUE_SGFS;
                }
                else if ( opd->options & X86IM_IO_IP_SGGS )
                {
                    io->seg = X86IM_IO_ROP_ID_GS;
                    X86IM_IO_IP_SET_SGGS( io );
                    io->prefix_values[ a ] = X86IM_IO_IP_VALUE_SGGS;
                }

                X86IM_IO_IF_SET_SGP( io );
                X86IM_IO_IP_SET_SGXS_POS( io, a );
                ++io->prefix_count;
            }
            else
            {
                break;
            }
        }

        if ( X86IM_IO_IS_MODE_64BIT( io ) &&
            ( ( opd->options & X86IM_GEN_OAT_QWORD ) ||
              ( opd->options & X86IM_IO_IP_REX ) ||
              ( opd->reg & 0x88 ) ||
              ( opd->mm.value & 0x880000 ) ) )
        {
            io->rexp = 0x40;

            if ( opd->options & X86IM_GEN_OAT_QWORD )
            {
                X86IM_IO_IP_SET_REX_W( io );
            }

            X86IM_IO_IF_SET_PFX( io );
            X86IM_IO_IP_SET_REX( io );
            ++io->prefix_count;
        }

        i = ( unsigned char * )&opd->code;
    }

    if ( !( itbl_ent = x86im_search_cmd( i, opd, io ) ) )
    {
        io->status = X86IM_STATUS_INVALID_OPCODE;
        return io->status;
    }

    if ( X86IM_CORE_OP_IS_GEN( opd ) )
    {
        i = &io->opcode[0];
    }

    io->opcode_count = ( unsigned char )itbl_ent->len;

    if ( itbl_ent->len > 1 )
    {
        i += itbl_ent->len - 1;
    }

    if ( ITE_BIT( itbl_ent ) )
    {
        if ( ITE_BIT_WB( itbl_ent ) )
        {
            X86IM_IO_IF_SET_WBIT( io );
            io->w_bit = *i & 0x1;
        }
        if ( ITE_BIT_W3( itbl_ent ) )
        {
            X86IM_IO_IF_SET_WBIT( io );

            io->w_bit = ( *i >> 3 ) & 0x1;
        }
        if ( ITE_BIT_SB( itbl_ent ) )
        {
            X86IM_IO_IF_SET_SBIT( io );
            io->s_bit = ( *i & 0x2 ) >> 1;
        }
        if ( ITE_BIT_DB( itbl_ent ) )
        {
            X86IM_IO_IF_SET_DBIT( io );
            io->d_bit = ( *i & 0x2 ) >> 1;
        }
        if ( ITE_BIT_GG( itbl_ent ) )
        {
            X86IM_IO_IF_SET_GGFLD( io );

            io->gg_fld = *i & 0x3;

            if ( ITE_BIT_NZ( itbl_ent ) )
            {
                io->id += ( io->gg_fld * 2 );
            }
        }
        if ( itbl_ent->extflg & (_ITE_BIT_NC|_ITE_BIT_NZ) )
        {
            if ( ITE_BIT_NZ( itbl_ent ) )
            {
                X86IM_IO_IF_SET_NZ( io );
            }
            else
            {
                X86IM_IO_IF_SET_NC( io );
            }
        }
        if ( ITE_BIT_MB( itbl_ent ) )
        {
            X86IM_IO_IF_SET_MODRM( io );
        }
    }

    if ( X86IM_IO_IP_HAS_ADSZ( io ) )
    {
        io->def_adsz >>= 1;
    }

    if ( ITE_ENC_FIXED( itbl_ent ) )
    {
        if ( ITE_ENC_F8( itbl_ent ) )
        {
            io->def_opsz = 1;
        }
        else if ( ITE_ENC_F16( itbl_ent ) )
        {
            io->def_opsz = 2;
        }
        else if ( ITE_ENC_F32( itbl_ent ) )
        {
            io->def_opsz = 4;
        }
        else
        {
            if ( X86IM_IO_IS_MODE_64BIT( io ) )
            {
                io->def_opsz = 8;
            }
        }
    }
    else
    {
        if ( X86IM_IO_IS_MODE_64BIT( io ) &&
             ITE_ENC_D64( itbl_ent ) )
        {
            io->def_opsz <<= 1;
        }
        if ( X86IM_IO_IP_HAS_OPSZ( io ) )
        {
            if ( !X86IM_IO_IS_MODE_64BIT( io ) ||
                 !ITE_ENC_NS( itbl_ent ) )
            {
                if ( io->somimp != X86IM_IO_IP_OPSZ )
                {
                    io->def_opsz >>= ( io->def_opsz / 4 );
                }
            }
        }
        if ( X86IM_IO_IP_HAS_REX( io ) &&
             X86IM_IO_IP_HAS_REX_W( io ) )
        {
            io->def_opsz = 8;
        }
        if ( X86IM_IO_IF_HAS_WBIT( io ) )
        {
            if ( io->w_bit == 0 )
            {
                io->def_opsz = 1;
            }
        }
    }

    io->len = itbl_ent->len +
              io->prefix_count;

    io->grp    = itbl_ent->grp;
    io->id     += itbl_ent->id;
    io->mnm    = itbl_ent->mnm;

    opd->itbl_ent = itbl_ent;

    for ( val = 0; val < ITE_MAX_OP; val++ )
    {
        op = itbl_ent->rop[ val ];

        if ( op == ITE_NOOP )
        {
            break;
        }

        x86im_core_process_op( opd,
                               op,
                               i );
        if ( io->status )
        {
            return io->status;
        }
    }

    io->len += X86IM_IO_IF_HAS_3DNS( io ) +
               X86IM_IO_IF_HAS_MODRM( io ) +
               X86IM_IO_IF_HAS_SIB( io ) +
               io->imm_size + io->disp_size;

    return io->status;
}

int __stdcall x86im_dec ( __inout x86im_instr_object *io,
                          __in unsigned long mode,
                          __in unsigned char *data )
{
    core_opdata opd;
    int i;

    for ( i = 0;
          i < sizeof( core_opdata );
          i++ )
    {
        *( char * )( ( char * )&opd + i ) = 0x0;
    }

    opd.io      = io;
    opd.options = mode;
    opd.instr   = data;

    return x86im_core( X86IM_CORE_OP_DEC, &opd );
}

int __stdcall x86im_gen ( __inout x86im_instr_object *io,
                          __in unsigned long options,
                          __in unsigned long code,
                          __in unsigned long reg,
                          __in unsigned long mem,
                          __in unsigned long long disp,
                          __in unsigned long long imm )
{
    core_opdata opd;
    int i;

    for ( i = 0;
          i < sizeof( core_opdata );
          i++ )
    {
        *( char * )( ( char * )&opd + i ) = 0x0;
    }

    opd.io         = io;
    opd.options    = options;
    opd.code       = code;

    opd.reg        = reg;
    opd.mm.value   = mem;
    opd.disp       = disp;
    opd.imm        = imm;

    return x86im_core( X86IM_CORE_OP_GEN, &opd );
}

int __stdcall x86im_enc( __inout x86im_instr_object *io,
                         __out unsigned char *instr )
{
    int i, pos;

    pos = io->prefix_count;
    if ( X86IM_IO_IP_HAS_REX( io ) ) --pos;

    for ( i = 0;
          i < pos;
          i++ )
    {
        instr[ i ] = io->prefix_values[ i ];
    }

    if ( X86IM_IO_IP_HAS_REX( io ) )
    {
        instr[ pos++ ] = io->rexp;
    }

    for ( i = 0;
          i < io->opcode_count;
          i++ )
    {
        instr[ pos++ ] = io->opcode[ i ];
    }

    if ( X86IM_IO_IF_HAS_MODRM( io ) )
    {
        instr[ pos++ ] = io->modrm;
    }

    if ( X86IM_IO_IF_HAS_SIB( io ) )
    {
        instr[ pos++ ] = io->sib;
    }

    if ( X86IM_IO_IF_HAS_MEM_OP( io ) &&
         X86IM_IO_MOP_AMC_HAS_DISP( io ) )
    {
        if ( io->disp_size == 1 )
        {
            instr[ pos ] = ( unsigned char )io->disp;
        }
        else if ( io->disp_size == 2 )
        {
            *( ( unsigned short * )( &instr[ pos ] ) )= ( unsigned short )io->disp;
        }
        else if ( io->disp_size == 4 )
        {
            *( ( unsigned long * )( &instr[ pos ] ) ) = ( unsigned long )io->disp;
        }
        else if ( io->disp_size == 8 )
        {
            *( ( unsigned long long * )( &instr[ pos ] ) ) = io->disp;
        }

        pos += io->disp_size;
    }

    if ( X86IM_IO_IF_HAS_IMM_OP( io ) )
    {
        if ( io->imm_size == 1 )
        {
            instr[ pos ] = ( unsigned char )io->imm;
        }
        else if ( io->imm_size == 2 )
        {
            *( ( unsigned short * )( &instr[ pos ] ) )= ( unsigned short )io->imm;
        }
        else if ( io->imm_size == 4 ||
                  io->imm_size == 3 )
        {
            *( ( unsigned long * )( &instr[ pos ] ) ) = ( unsigned long )io->imm;
        }
        else if ( io->imm_size == 8 )
        {
            *( ( unsigned long long * )( &instr[ pos ] ) ) = io->imm;
        }

        pos += io->imm_size;
    }

    if ( X86IM_IO_IF_HAS_SEL( io ) )
    {
        *( ( unsigned short * )( &instr[ pos ] ) ) = io->selector;
        pos += 2;
    }

    if ( X86IM_IO_IF_HAS_3DNS( io ) )
    {
        instr[ pos++ ] = X86IM_IO_GET_3DNS( io );
    }

    return pos;
}
