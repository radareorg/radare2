cmake_minimum_required(VERSION 3.9)

set(spp_files
    spp.c)
add_library(libr2spp ${SHLR_LIB_TYPE} ${spp_files})
target_include_directories(libr2spp
        PUBLIC
        ${PLATFORM_INC})
set(LIBR2SPP_COMPILE_FLAGS
        "-DHAVE_R_UTIL")
target_compile_options(libr2spp PUBLIC ${LIBR2SPP_COMPILE_FLAGS})