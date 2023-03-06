if get_option('enable_libfuzzer')
  targets = [
    'anal',
    'bin',
    'bin2',
    'fs',
    'dwarf',
    'bin_demangle',
    'ia',
    'cmd',
    'pdb_parse',
    'pkcs7_parse',
    'protobuf_decode',
    'punycode_decode',
    'run_parseline',
    'x509_parse',
  ]

  foreach target : targets
    exe = executable('fuzz_@0@'.format(target), 'fuzz_@0@.c'.format(target),
      include_directories: [platform_inc],
      dependencies: [
        r_bin_dep,
        r_core_dep,
        r_util_dep,
        r_socket_dep,
      ],
      install: false,
      implicit_include_directories: false,
      c_args : '-fsanitize=fuzzer',
      link_args : '-fsanitize=fuzzer'
    )
  endforeach
endif
