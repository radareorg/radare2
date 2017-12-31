cmake_minimum_required(VERSION 3.9)

set(tcc_files
    libtcc.c
    tccgen.c
    tccpp.c)
add_library(libr2tcc ${SHLR_LIB_TYPE} ${tcc_files})
target_include_directories(libr2tcc
        PUBLIC
        ${PLATFORM_INC})