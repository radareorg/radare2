# handle zlib dependency
zlib_dep = dependency('zlib', required: false)
if not zlib_dep.found() or not get_option('use_sys_zlib')
  message('Use subprojected zlib')

  zlib_proj = subproject('zlib')
  zlib_dep = zlib_proj.get_variable('zlib_dep')
else
  message('Use system-provided zlib library')
endif

# handle zip dependency
zip_dep = dependency('libzip', required: false)
if not zip_dep.found() or not get_option('use_sys_zip')
  message('Use subprojected zip')

  zip_proj = subproject('zip')
  zip_dep = zip_proj.get_variable('zip_dep')
else
  message('Use system-provided zip library')
endif

