cmake_minimum_required(VERSION 3.9)

set(sdb_files
    src/array.c
    src/base64.c
    src/buffer.c
    src/cdb.c
    src/cdb_make.c
    src/disk.c
    src/fmt.c
    src/ht.c
    src/journal.c
    src/json.c
    src/lock.c
    src/ls.c
    #src/main.c
    src/match.c
    src/ns.c
    src/num.c
    src/query.c
    src/sdb.c
    src/sdbht.c
    src/util.c)
add_library(libr2sdb ${SHLR_LIB_TYPE} ${sdb_files})
target_include_directories(libr2sdb
        PUBLIC
        ${PLATFORM_INC}
        src
        ../../libr/include/sdb)