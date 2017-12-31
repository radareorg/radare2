cmake_minimum_required(VERSION 3.8)

set(files
	crypto.c
	p/crypto_aes.c
	p/crypto_aes_algo.c
	p/crypto_aes_cbc.c
	p/crypto_base64.c
	p/crypto_base91.c
	p/crypto_blowfish.c
	p/crypto_cps2.c
	p/crypto_des.c
	p/crypto_punycode.c
	p/crypto_rc2.c
	p/crypto_rc4.c
	p/crypto_rc6.c
	p/crypto_rol.c
	p/crypto_ror.c
	p/crypto_rot.c
	p/crypto_xor.c
	p/crypto_serpent.c
	p/crypto_serpent_algo.c)

add_library(r_crypto ${LIBR_LIB_TYPE} ${files})
target_include_directories(r_crypto
		PUBLIC
		${PLATFORM_INC})
set(R_CRYPTO_COMPILE_FLAGS 
	"-DCORELIB=1"
	"-I${CMAKE_CURRENT_BINARY_DIR}/../..")
target_compile_options(r_crypto PUBLIC ${R_CRYPTO_COMPILE_FLAGS})
target_link_libraries(r_crypto r_util)

