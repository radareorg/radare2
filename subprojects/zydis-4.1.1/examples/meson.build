examples_req = examples.enabled()

if examples_req
  if decoder.enabled() and formatter.enabled()
    executable('DisassembleSimple', 'DisassembleSimple.c', dependencies: [zydis_dep])
    executable('Disassemble', 'Disassemble.c', dependencies: [zydis_dep])
    executable('Formatter01', 'Formatter01.c', dependencies: [zydis_dep])
    executable('Formatter02', 'Formatter02.c', dependencies: [zydis_dep])
    executable('Formatter03', 'Formatter03.c', dependencies: [zydis_dep])
    executable(
      'ZydisPerfTest',
      'ZydisPerfTest.c',
      c_args: host_machine.system() in ['linux', 'freebsd'] ? ['-D_GNU_SOURCE'] : [],
      dependencies: [zydis_dep],
    )
  endif

  if encoder.enabled()
    executable('EncodeMov', 'EncodeMov.c', dependencies: [zydis_dep])
    executable('EncodeFromScratch', 'EncodeFromScratch.c', dependencies: [zydis_dep])
    executable('RewriteCode', 'RewriteCode.c', dependencies: [zydis_dep])
  endif
endif

summary(
  {'examples': examples_req},
  section: 'Features',
)
