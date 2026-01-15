fs = import('fs')

if not fs.is_file('r2plugins.h')
  deps_h = configure_file(
    input: 'r2plugins.h.in',
    output: 'r2plugins.h',
    configuration: configuration_data()
  )
endif

if fs.is_file('p/meson.build')
  subdir('p')
endif
