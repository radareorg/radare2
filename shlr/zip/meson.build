# handle zip dependency (optional)
if get_option('use_zip')
  if get_option('use_sys_zip')
    message('Use system-provided zip and zlib libraries')
    zip_dep = dependency('libzip', required: true)
    zlib_dep = dependency('zlib', required: true)
    zip_dep = declare_dependency(dependencies: [zip_dep, zlib_dep])
  else
    if get_option('use_otezip')
      message('Use otezip as libzip replacement (with bundled zlib)')
    else
      # If use_zip is enabled but no specific implementation chosen,
      # automatically use otezip as the default bundled implementation
      message('Using otezip as default libzip implementation (with bundled zlib)')
    endif
    otezip_proj = subproject('otezip')
    otezip_src = otezip_proj.get_variable('otezip_src')
    otezip_inc = otezip_proj.get_variable('otezip_inc')
    otezip_hidden_lib = static_library('otezip-hidden',
      otezip_src,
      include_directories: otezip_inc,
      gnu_symbol_visibility: 'hidden',
      pic: true,
      install: false
    )
    zip_dep = declare_dependency(
      link_with: otezip_hidden_lib,
      include_directories: otezip_inc
    )
    zlib_dep = declare_dependency()  # otezip has bundled zlib
  endif
else
  message('Zip support disabled (use_zip=false)')
  zip_dep = declare_dependency() # empty when disabled
  zlib_dep = declare_dependency()
endif
