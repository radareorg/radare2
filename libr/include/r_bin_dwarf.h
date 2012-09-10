#ifndef _INCLUDE_BIN_DWARF_H_
#define _INCLUDE_BIN_DWARF_H_

#define DW_EXTENDED_OPCODE 0
#define LOP_EXTENDED 1
#define LOP_DISCARD  2
#define LOP_STANDARD 3
#define LOP_SPECIAL  4

#define DW_LNS_copy                     0x01
#define DW_LNS_advance_pc               0x02
#define DW_LNS_advance_line             0x03
#define DW_LNS_set_file                 0x04
#define DW_LNS_set_column               0x05
#define DW_LNS_negate_stmt              0x06
#define DW_LNS_set_basic_block          0x07
#define DW_LNS_const_add_pc             0x08
#define DW_LNS_fixed_advance_pc         0x09
#define DW_LNS_set_prologue_end         0x0a /* DWARF3 */
#define DW_LNS_set_epilogue_begin       0x0b /* DWARF3 */
#define DW_LNS_set_isa                  0x0c /* DWARF3 */
/* Line number extended opcode name. */
#define DW_LNE_end_sequence             0x01
#define DW_LNE_set_address              0x02
#define DW_LNE_define_file              0x03
#define DW_LNE_set_discriminator        0x04  /* DWARF4 */

/* HP extensions. */
#define DW_LNE_HP_negate_is_UV_update       0x11 /* 17 HP */
#define DW_LNE_HP_push_context              0x12 /* 18 HP */
#define DW_LNE_HP_pop_context               0x13 /* 19 HP */
#define DW_LNE_HP_set_file_line_column      0x14 /* 20 HP */
#define DW_LNE_HP_set_routine_name          0x15 /* 21 HP */
#define DW_LNE_HP_set_sequence              0x16 /* 22 HP */
#define DW_LNE_HP_negate_post_semantics     0x17 /* 23 HP */
#define DW_LNE_HP_negate_function_exit      0x18 /* 24 HP */
#define DW_LNE_HP_negate_front_end_logical  0x19 /* 25 HP */
#define DW_LNE_HP_define_proc               0x20 /* 32 HP */

#define DW_LNE_lo_user                  0x80 /* DWARF3 */
#define DW_LNE_hi_user                  0xff /* DWARF3 */

/* debug_info tags */
#define DW_TAG_array_type               0x01
#define DW_TAG_class_type               0x02
#define DW_TAG_entry_point              0x03
#define DW_TAG_enumeration_type         0x04
#define DW_TAG_formal_parameter         0x05
#define DW_TAG_imported_declaration     0x08
#define DW_TAG_label                    0x0a
#define DW_TAG_lexical_block            0x0b
#define DW_TAG_member                   0x0d
#define DW_TAG_pointer_type             0x0f
#define DW_TAG_reference_type           0x10
#define DW_TAG_compile_unit             0x11 // 
#define DW_TAG_string_type              0x12
#define DW_TAG_structure_type           0x13
#define DW_TAG_subroutine_type          0x15
#define DW_TAG_typedef                  0x16
#define DW_TAG_union_type               0x17
#define DW_TAG_unspecified_parameters   0x18
#define DW_TAG_variant                  0x19
#define DW_TAG_common_block             0x1a
#define DW_TAG_common_inclusion         0x1b
#define DW_TAG_inheritance              0x1c
#define DW_TAG_inlined_subroutine       0x1d
#define DW_TAG_module                   0x1e
#define DW_TAG_ptr_to_member_type       0x1f
#define DW_TAG_set_type                 0x20
#define DW_TAG_subrange_type            0x21
#define DW_TAG_with_stmt                0x22
#define DW_TAG_access_declaration       0x23
#define DW_TAG_base_type                0x24
#define DW_TAG_catch_block              0x25
#define DW_TAG_const_type               0x26
#define DW_TAG_constant                 0x27
#define DW_TAG_enumerator               0x28
#define DW_TAG_file_type                0x29
#define DW_TAG_friend                   0x2a
#define DW_TAG_namelist                 0x2b
        /*  Early releases of this header had the following
            misspelled with a trailing 's' */
#define DW_TAG_namelist_item            0x2c /* DWARF3/2 spelling */
#define DW_TAG_namelist_items           0x2c /* SGI misspelling/typo */
#define DW_TAG_packed_type              0x2d
#define DW_TAG_subprogram               0x2e
        /*  The DWARF2 document had two spellings of the following
            two TAGs, DWARF3 specifies the longer spelling. */
#define DW_TAG_template_type_parameter  0x2f /* DWARF3/2 spelling*/
#define DW_TAG_template_type_param      0x2f /* DWARF2   spelling*/
#define DW_TAG_template_value_parameter 0x30 /* DWARF3/2 spelling*/
#define DW_TAG_template_value_param     0x30 /* DWARF2   spelling*/
#define DW_TAG_thrown_type              0x31
#define DW_TAG_try_block                0x32
#define DW_TAG_variant_part             0x33
#define DW_TAG_variable                 0x34
#define DW_TAG_volatile_type            0x35
#define DW_TAG_dwarf_procedure          0x36  /* DWARF3 */
#define DW_TAG_restrict_type            0x37  /* DWARF3 */
#define DW_TAG_interface_type           0x38  /* DWARF3 */
#define DW_TAG_namespace                0x39  /* DWARF3 */
#define DW_TAG_imported_module          0x3a  /* DWARF3 */
#define DW_TAG_unspecified_type         0x3b  /* DWARF3 */
#define DW_TAG_partial_unit             0x3c  /* DWARF3 */
#define DW_TAG_imported_unit            0x3d  /* DWARF3 */
        /*  Do not use DW_TAG_mutable_type */
#define DW_TAG_mutable_type 0x3e /* Withdrawn from DWARF3 by DWARF3f. */
#define DW_TAG_condition                0x3f  /* DWARF3f */
#define DW_TAG_shared_type              0x40  /* DWARF3f */
#define DW_TAG_type_unit                0x41  /* DWARF4 */
#define DW_TAG_rvalue_reference_type    0x42  /* DWARF4 */
#define DW_TAG_template_alias           0x43  /* DWARF4 */

typedef struct {
	ut32 total_length;
	ut16 version;
	ut32 plen;
	ut8 mininstlen;
	ut8 is_stmt;
	char line_base;
	ut8 line_range;
	ut8 opcode_base;
	ut32 oplentable[12];
	const char **incdirs;
	const char *file[16];
	//RBinDwarfInfoHeader
} RBinDwarfInfoHeader;

typedef struct {
	ut64 address;
	unsigned int file;
	unsigned int line;
	unsigned int column;
	int is_stmt;
	int basic_block;
	int end_sequence;
} RBinDwarfState;

typedef struct {
	ut64 address;
	const char *file;
	unsigned int line;
	unsigned int column;
} RBinDwarfRow;
#define r_bin_dwarf_line_new(o,a,f,l) o->address=a, o->file = strdup (f?f:""), o->line = l, o->column =0,o

R_API int r_bin_dwarf_parse_info_raw(const ut8 *obuf);

#endif
