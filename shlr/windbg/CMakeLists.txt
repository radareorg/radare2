cmake_minimum_required(VERSION 3.9)

set(windbg_files
    iob_pipe.c
    kd.c
    transport.c
    windbg.c)
add_library(libr2windbg ${SHLR_LIB_TYPE} ${windbg_files})
target_include_directories(libr2windbg
        PUBLIC
        ${PLATFORM_INC})