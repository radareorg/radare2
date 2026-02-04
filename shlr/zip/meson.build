# handle zip dependency (optional)
if get_option('use_zip')
  if get_option('use_sys_zip')
    message('Use system-provided zip and zlib libraries')
    zip_dep = dependency('libzip', required: true)
    zlib_dep = dependency('zlib', required: true)
    zip_dep = declare_dependency(dependencies: [zip_dep, zlib_dep])
  elif get_option('use_otezip')
    message('Use otezip as libzip replacement (with bundled zlib)')
    otezip_proj = subproject('otezip')
    zip_dep = otezip_proj.get_variable('otezip_dep')
    zlib_dep = declare_dependency()  # otezip has bundled zlib
  else
    # If use_zip is enabled but no specific implementation chosen,
    # automatically use otezip as the default bundled implementation
    message('Using otezip as default libzip implementation (with bundled zlib)')
    otezip_proj = subproject('otezip')
    zip_dep = otezip_proj.get_variable('otezip_dep')
    zlib_dep = declare_dependency()  # otezip has bundled zlib
  endif
else
  message('Zip support disabled (use_zip=false)')
  zip_dep = declare_dependency() # empty when disabled
  zlib_dep = declare_dependency()
endif