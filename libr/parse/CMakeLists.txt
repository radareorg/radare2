cmake_minimum_required(VERSION 3.8)

set(files
	code.c
	parse.c
	p/parse_6502_pseudo.c
	p/parse_arm_pseudo.c
	p/parse_att2intel.c
	p/parse_dalvik_pseudo.c
	p/parse_m68k_pseudo.c
	p/parse_mips_pseudo.c
	p/parse_mreplace.c
	p/parse_ppc_pseudo.c
	p/parse_x86_pseudo.c
	p/parse_z80_pseudo.c
	p/parse_sh_pseudo.c
	p/parse_avr_pseudo.c
	p/parse_mreplace/mreplace.c
	p/parse_mreplace/mmemory.c)

add_library(r_parse ${LIBR_LIB_TYPE} ${files}
		$<TARGET_OBJECTS:libr2tcc>
		$<TARGET_OBJECTS:libr2sdb>)
target_include_directories(r_parse
		PUBLIC
		${PLATFORM_INC}
		../../shlr/tcc)
set(R_PARSE_COMPILE_FLAGS 
	"-DCORELIB=1"
	"-I${CMAKE_CURRENT_BINARY_DIR}/../..")
target_compile_options(r_parse PUBLIC ${R_PARSE_COMPILE_FLAGS})
target_link_libraries(r_parse r_util r_flag r_syscall r_reg)
