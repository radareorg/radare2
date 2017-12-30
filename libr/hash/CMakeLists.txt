cmake_minimum_required(VERSION 3.8)

set(files
	adler32.c
	calc.c
	crca.c
	entropy.c
	hamdist.c
	hash.c
	luhn.c
	md4.c
	md5.c
	sha1.c
	sha2.c
	state.c
	xxhash.c)

add_library(r_hash ${LIBR_LIB_TYPE} ${files})
target_include_directories(r_hash
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(r_hash r_util)
