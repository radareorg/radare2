cmake_minimum_required(VERSION 3.9)

set(udis86_files
    decode.c
    itab.c
    syn.c
    syn-att.c
    syn-intel.c
    udis86.c)
add_library(libr2udis86 ${SHLR_LIB_TYPE} ${udis86_files})
target_include_directories(libr2udis86
        PUBLIC
        ${PLATFORM_INC})
