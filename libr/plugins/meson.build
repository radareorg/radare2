deps_h = configure_file(
  input: 'deps.h.in',
  output: 'deps.h',
  configuration: configuration_data()
)

fs = import('fs')
if fs.is_file('p/meson.build')
  subdir('deps')
endif
