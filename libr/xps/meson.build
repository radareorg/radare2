fs = import('fs')

# Initialize external plugin variables (these may be used by external plugins)
# Must be done before subdirectory processing
if not is_variable('r_core_additional_sources')
  r_core_additional_sources = []
endif
if not is_variable('r_core_additional_inc')
  r_core_additional_inc = []
endif

# Generate empty r2plugins.h header file (Make creates this with plugin includes)
# For Meson, this is minimal since we directly append sources
deps_h = configure_file(
  input: 'r2plugins.h.in',
  output: 'r2plugins.h',
  configuration: configuration_data()
)

# Process external plugins
if fs.is_file('p/meson.build')
  subdir('p')
endif
