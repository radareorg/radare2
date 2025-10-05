
cli_option = get_option('cli')
if cli_option.auto()
  cli_enabled = not meson.is_subproject()
else
  cli_enabled = cli_option.enabled()
endif
if cli_enabled
  if get_option('blob')
    subdir('blob')
  else
    subdir('rahash2')
    subdir('rarun2')
    subdir('rasm2')
    subdir('rabin2')
    subdir('radare2')
    subdir('ragg2')
    subdir('r2agent')
    subdir('radiff2')
    subdir('rapatch2')
    subdir('rafind2')
    subdir('rasign2')
    subdir('rafs2')
    subdir('ravc2')
    subdir('rax2')
  endif
  subdir('r2pm')
  subdir('r2r')
endif

