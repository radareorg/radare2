"td enum mach0_build_platform {MACOS=1, IOS=2, TVOS=3, WATCHOS=4, BRIDGEOS=5, IOSMAC=6, IOSSIMULATOR=7, TVOSSIMULATOR=8, WATCHOSSIMULATOR=9};"
"td enum mach0_build_tool {CLANG=1, SWIFT=2, LD=3};"
"td enum mach0_load_command_type { LC_SEGMENT=0x00000001ULL, LC_SYMTAB=0x00000002ULL, LC_SYMSEG=0x00000003ULL, LC_THREAD=0x00000004ULL, LC_UNIXTHREAD=0x00000005ULL, LC_LOADFVMLIB=0x00000006ULL, LC_IDFVMLIB=0x00000007ULL, LC_IDENT=0x00000008ULL, LC_FVMFILE=0x00000009ULL, LC_PREPAGE=0x0000000aULL, LC_DYSYMTAB=0x0000000bULL, LC_LOAD_DYLIB=0x0000000cULL, LC_ID_DYLIB=0x0000000dULL, LC_LOAD_DYLINKER=0x0000000eULL, LC_ID_DYLINKER=0x0000000fULL, LC_PREBOUND_DYLIB=0x00000010ULL, LC_ROUTINES=0x00000011ULL, LC_SUB_FRAMEWORK=0x00000012ULL, LC_SUB_UMBRELLA=0x00000013ULL, LC_SUB_CLIENT=0x00000014ULL, LC_SUB_LIBRARY=0x00000015ULL, LC_TWOLEVEL_HINTS=0x00000016ULL, LC_PREBIND_CKSUM=0x00000017ULL, LC_LOAD_WEAK_DYLIB=0x80000018ULL, LC_SEGMENT_64=0x00000019ULL, LC_ROUTINES_64=0x0000001aULL, LC_UUID=0x0000001bULL, LC_RPATH=0x8000001cULL, LC_CODE_SIGNATURE=0x0000001dULL, LC_SEGMENT_SPLIT_INFO=0x0000001eULL, LC_REEXPORT_DYLIB=0x8000001fULL, LC_LAZY_LOAD_DYLIB=0x00000020ULL, LC_ENCRYPTION_INFO=0x00000021ULL, LC_DYLD_INFO=0x00000022ULL, LC_DYLD_INFO_ONLY=0x80000022ULL, LC_LOAD_UPWARD_DYLIB=0x80000023ULL, LC_VERSION_MIN_MACOSX=0x00000024ULL, LC_VERSION_MIN_IPHONEOS=0x00000025ULL, LC_FUNCTION_STARTS=0x00000026ULL, LC_DYLD_ENVIRONMENT=0x00000027ULL, LC_MAIN=0x80000028ULL, LC_DATA_IN_CODE=0x00000029ULL, LC_SOURCE_VERSION=0x0000002aULL, LC_DYLIB_CODE_SIGN_DRS=0x0000002bULL, LC_ENCRYPTION_INFO_64=0x0000002cULL, LC_LINKER_OPTION=0x0000002dULL, LC_LINKER_OPTIMIZATION_HINT=0x0000002eULL, LC_VERSION_MIN_TVOS=0x0000002fULL, LC_VERSION_MIN_WATCHOS=0x00000030ULL, LC_NOTE=0x00000031ULL, LC_BUILD_VERSION=0x00000032ULL };"
"td enum mach0_header_filetype {MH_OBJECT=1, MH_EXECUTE=2, MH_FVMLIB=3, MH_CORE=4, MH_PRELOAD=5, MH_DYLIB=6, MH_DYLINKER=7, MH_BUNDLE=8, MH_DYLIB_STUB=9, MH_DSYM=10, MH_KEXT_BUNDLE=11};"
"td enum mach0_header_flags {MH_NOUNDEFS=1, MH_INCRLINK=2,MH_DYLDLINK=4,MH_BINDATLOAD=8,MH_PREBOUND=0x10, MH_SPLIT_SEGS=0x20,MH_LAZY_INIT=0x40,MH_TWOLEVEL=0x80, MH_FORCE_FLAT=0x100,MH_NOMULTIDEFS=0x200,MH_NOFIXPREBINDING=0x400, MH_PREBINDABLE=0x800, MH_ALLMODSBOUND=0x1000, MH_SUBSECTIONS_VIA_SYMBOLS=0x2000, MH_CANONICAL=0x4000,MH_WEAK_DEFINES=0x8000, MH_BINDS_TO_WEAK=0x10000,MH_ALLOW_STACK_EXECUTION=0x20000, MH_ROOT_SAFE=0x40000,MH_SETUID_SAFE=0x80000, MH_NO_REEXPORTED_DYLIBS=0x100000,MH_PIE=0x200000, MH_DEAD_STRIPPABLE_DYLIB=0x400000, MH_HAS_TLV_DESCRIPTORS=0x800000, MH_NO_HEAP_EXECUTION=0x1000000};"
"td enum mach0_section_types {S_REGULAR=0, S_ZEROFILL=1, S_CSTRING_LITERALS=2, S_4BYTE_LITERALS=3, S_8BYTE_LITERALS=4, S_LITERAL_POINTERS=5, S_NON_LAZY_SYMBOL_POINTERS=6, S_LAZY_SYMBOL_POINTERS=7, S_SYMBOL_STUBS=8, S_MOD_INIT_FUNC_POINTERS=9, S_MOD_TERM_FUNC_POINTERS=0xa, S_COALESCED=0xb, S_GB_ZEROFILL=0xc, S_INTERPOSING=0xd, S_16BYTE_LITERALS=0xe, S_DTRACE_DOF=0xf, S_LAZY_DYLIB_SYMBOL_POINTERS=0x10, S_THREAD_LOCAL_REGULAR=0x11, S_THREAD_LOCAL_ZEROFILL=0x12, S_THREAD_LOCAL_VARIABLES=0x13, S_THREAD_LOCAL_VARIABLE_POINTERS=0x14, S_THREAD_LOCAL_INIT_FUNCTION_POINTERS=0x15, S_INIT_FUNC_OFFSETS=0x16};"
"td enum mach0_section_attrs {S_ATTR_PURE_INSTRUCTIONS=0x800000ULL, S_ATTR_NO_TOC=0x400000ULL, S_ATTR_STRIP_STATIC_SYMS=0x200000ULL, S_ATTR_NO_DEAD_STRIP=0x100000ULL, S_ATTR_LIVE_SUPPORT=0x080000ULL, S_ATTR_SELF_MODIFYING_CODE=0x040000ULL, S_ATTR_DEBUG=0x020000ULL, S_ATTR_SOME_INSTRUCTIONS=0x000004ULL, S_ATTR_EXT_RELOC=0x000002ULL, S_ATTR_LOC_RELOC=0x000001ULL};"
pf.mach0_header xxx[4]Edd[4]B magic cputype cpusubtype (mach0_header_filetype)filetype ncmds sizeofcmds (mach0_header_flags)flags
pf.mach0_segment [4]Ed[16]zxxxxoodx (mach0_load_command_type)cmd cmdsize segname vmaddr vmsize fileoff filesize maxprot initprot nsects flags
pf.mach0_segment64 [4]Ed[16]zqqqqoodx (mach0_load_command_type)cmd cmdsize segname vmaddr vmsize fileoff filesize maxprot initprot nsects flags
pf.mach0_symtab_command [4]Edxdxd (mach0_load_command_type)cmd cmdsize symoff nsyms stroff strsize
pf.mach0_dysymtab_command [4]Edddddddddddxdxdxxxd (mach0_load_command_type)cmd cmdsize ilocalsym nlocalsym iextdefsym nextdefsym iundefsym nundefsym tocoff ntoc moddtaboff nmodtab extrefsymoff nextrefsyms inddirectsymoff nindirectsyms extreloff nextrel locreloff nlocrel
pf.mach0_section [16]z[16]zxxxxxx[1]E[3]Bxx sectname segname addr size offset align reloff nreloc (mach0_section_types)flags_type (mach0_section_attrs)flags_attr reserved1 reserved2
pf.mach0_section64 [16]z[16]zqqxxxx[1]E[3]Bxxx sectname segname addr size offset align reloff nreloc (mach0_section_types)flags_type (mach0_section_attrs)flags_attr reserved1 reserved2 reserved3
pf.mach0_dylib xxxxz name_offset timestamp current_version compatibility_version name
pf.mach0_dylib_command [4]Ed? (mach0_load_command_type)cmd cmdsize (mach0_dylib)dylib
pf.mach0_id_dylib_command [4]Ed? (mach0_load_command_type)cmd cmdsize (mach0_dylib)dylib
pf.mach0_uuid_command [4]Ed[16]b (mach0_load_command_type)cmd cmdsize uuid
pf.mach0_rpath_command [4]Edxz (mach0_load_command_type)cmd cmdsize path_offset path
pf.mach0_entry_point_command [4]Edqq (mach0_load_command_type)cmd cmdsize entryoff stacksize
pf.mach0_encryption_info64_command [4]Edxddx (mach0_load_command_type)cmd cmdsize offset size id padding
pf.mach0_encryption_info_command [4]Edxdd (mach0_load_command_type)cmd cmdsize offset size id
pf.mach0_code_signature_command [4]Edxd (mach0_load_command_type)cmd cmdsize offset size
pf.mach0_dyld_info_only_command [4]Edxdxdxdxdxd (mach0_load_command_type)cmd cmdsize rebase_off rebase_size bind_off bind_size weak_bind_off weak_bind_size lazy_bind_off lazy_bind_size export_off export_size
pf.mach0_load_dylinker_command [4]Edxz (mach0_load_command_type)cmd cmdsize name_offset name
pf.mach0_id_dylinker_command [4]Edxz (mach0_load_command_type)cmd cmdsize name_offset name
pf.mach0_build_version_command [4]Ed[4]Exxd (mach0_load_command_type)cmd cmdsize (mach0_build_platform)platform minos sdk ntools
pf.mach0_build_version_tool [4]Ex (mach0_build_tool)tool version
pf.mach0_source_version_command [4]Edq (mach0_load_command_type)cmd cmdsize version
pf.mach0_function_starts_command [4]Edxd (mach0_load_command_type)cmd cmdsize offset size
pf.mach0_data_in_code_command [4]Edxd (mach0_load_command_type)cmd cmdsize offset size
pf.mach0_version_min_command [4]Edxx (mach0_load_command_type)cmd cmdsize version reserved
pf.mach0_segment_split_info_command [4]Edxd (mach0_load_command_type)cmd cmdsize offset size
pf.mach0_unixthread_command [4]Eddd (mach0_load_command_type)cmd cmdsize flavor count
pf.mach0_code_directory exxxxxxxxxbbbb magic length version flags hashoff identoff nspecialslots ncodeslots codelimit hashsize hashtype spare pagesize
