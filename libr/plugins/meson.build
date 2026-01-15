fs = import('fs')

if not fs.is_file('deps.h')
  deps_h = configure_file(
    input: 'deps.h.in',
    output: 'deps.h',
    configuration: configuration_data()
  )
endif

if fs.is_file('p/meson.build')
  subdir('p')
endif
