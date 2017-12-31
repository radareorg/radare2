cmake_minimum_required(VERSION 3.9)

set(ar_files
        ar.c)
add_library(libr2ar OBJECT ${ar_files})
target_include_directories(libr2ar
        PUBLIC
        ${PLATFORM_INC}
        ar)