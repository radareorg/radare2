tools_req = tools.enabled()

llvm_fuzz = get_option('llvm-fuzz')

zydisinfo_exe = disabler()
zydisfuzzdecoder_exe = disabler()
zydisfuzzencoder_exe = disabler()
zydisfuzzreencoding_exe = disabler()
zydistestencoderabsolute_exe = disabler()
if tools_req
  if decoder.enabled() and formatter.enabled() and minimal.disabled()
    executable(
      'ZydisDisasm',
      files(
        'ZydisDisasm.c',
        'ZydisToolsShared.c',
        'ZydisToolsShared.h',
      ),
      dependencies: [zydis_dep],
      install: true,
    )

    zydisfuzzdecoder_exe = executable(
      'ZydisFuzzDecoder',
      files(
        'ZydisFuzzDecoder.c',
        'ZydisFuzzShared.c',
        'ZydisFuzzShared.h',
      ),
      dependencies: [zydis_dep],
      c_args: llvm_fuzz ? ['-DZYDIS_LIBFUZZER'] : [],
    )

    if encoder.enabled()
      zydisfuzzencoder_exe = executable(
        'ZydisFuzzEncoder',
        files(
          'ZydisFuzzEncoder.c',
          'ZydisFuzzShared.c',
          'ZydisFuzzShared.h',
        ),
        dependencies: [zydis_dep],
        c_args: llvm_fuzz ? ['-DZYDIS_LIBFUZZER'] : [],
      )
      zydisfuzzreencoding_exe = executable(
        'ZydisFuzzReEncoding',
        files(
          'ZydisFuzzReEncoding.c',
          'ZydisFuzzShared.c',
          'ZydisFuzzShared.h',
        ),
        dependencies: [zydis_dep],
        c_args: llvm_fuzz ? ['-DZYDIS_LIBFUZZER'] : [],
      )
      zydistestencoderabsolute_exe = executable(
        'ZydisTestEncoderAbsolute',
        files(
          'ZydisTestEncoderAbsolute.c',
        ),
        src + hdrs,
        c_args: ['-DZYDIS_STATIC_BUILD'],
        include_directories: [inc, inc_private],
        implicit_include_directories: false,
        dependencies: [zycore_dep],
        build_by_default: false,
      )
    endif

    zydisinfo_exe = executable(
      'ZydisInfo',
      files(
        'ZydisInfo.c',
        'ZydisToolsShared.c',
        'ZydisToolsShared.h',
      ),
      dependencies: [zydis_dep],
      install: true,
    )
  endif
endif

summary(
  {'tools': tools_req, 'llvm-fuzz': llvm_fuzz},
  section: 'Features',
)
