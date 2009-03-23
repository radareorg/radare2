#ifndef _INCLUDE_CONFIG_H_
#define _INCLUDE_CONFIG_H_

/* inlined APIs */
#define R_INLINE 0

#define R_ASM_STATIC_PLUGINS \
	&r_asm_plugin_java, \
	&r_asm_plugin_x86_olly, \
	&r_asm_plugin_mips, \
	0

#define R_BIN_STATIC_PLUGINS \
	0

#define R_BININFO_STATIC_PLUGINS \
	&r_bininfo_plugin_addr2line, \
	0

#endif
