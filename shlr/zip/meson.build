# handle zlib dependency
zlib_dep = dependency('zlib', version : '>=1.2.8', required: false, static: get_option('static_runtime'))
if not zlib_dep.found() or not get_option('use_sys_zlib')
  message('Use subprojected zlib')

  zlib_proj = subproject('zlib', default_options: ['default_library=static', 'werror=false'])
  zlib_dep = zlib_proj.get_variable('zlib_dep')
else
  message('Use system-provided zlib library')
endif

# handle zip dependency
zip_dep = dependency('libzip', required: false, static: get_option('static_runtime'))
if not zip_dep.found() or not get_option('use_sys_zip')
  message('Use subprojected zip')

  zip_proj = subproject('zip', default_options: [
    'default_library=static',
    'werror=false',
    'static_runtime=@0@'.format(get_option('static_runtime')),
    ])
  zip_dep = zip_proj.get_variable('zip_dep')
else
  message('Use system-provided zip library')
endif

