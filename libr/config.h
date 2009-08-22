#ifndef _INCLUDE_CONFIG_H_
#define _INCLUDE_CONFIG_H_

#define R_DEBUG 0
#define R_RTDEBUG 1

/* inlined APIs */
#define R_INLINE 0

#define DEFAULT_ARCH "x86"

#define R_ASM_STATIC_PLUGINS \
	&r_asm_plugin_java, \
	&r_asm_plugin_x86_olly, \
	&r_asm_plugin_x86_nasm, \
	&r_asm_plugin_mips, \
	0

#define R_PARSE_STATIC_PLUGINS \
	&r_parse_plugin_dummy, \
	&r_parse_plugin_x86_pseudo, \
	&r_parse_plugin_mreplace, \
	0

#define R_BIN_STATIC_PLUGINS \
	&r_bin_plugin_elf , \
	&r_bin_plugin_elf64 , \
	&r_bin_plugin_pe , \
	&r_bin_plugin_pe64 , \
	&r_bin_plugin_java , \
	&r_bin_plugin_dummy , \
	0

#define R_BININFO_STATIC_PLUGINS \
	&r_bininfo_plugin_addr2line, \
	0

#define R_BP_STATIC_PLUGINS \
	&r_bp_plugin_x86, \
	0

#define R_DEBUG_STATIC_PLUGINS \
	&r_debug_plugin_ptrace, \
	0

#endif
