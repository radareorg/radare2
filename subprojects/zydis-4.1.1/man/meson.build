ronn_exe = find_program('ronn', required: man)
man_req = ronn_exe.found()

if man_req
  man_names = [
    'ZydisDisasm.1',
    'ZydisInfo.1',
  ]

  foreach page : man_names
    custom_target(
      page,
      input: files(f'@page@.ronn'),
      command: [ronn_exe, '--roff', '--output-dir', '@OUTDIR@', '@INPUT@'],
      output: page,
      install: true,
      install_dir: datadir / 'man' / 'man1',
    )
  endforeach
endif

summary(
  {'man': man_req},
  section: 'Features',
)
