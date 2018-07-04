executable('rabin2', 'rabin2.c',
  include_directories: [platform_inc],
  link_with: [
    r_util, r_cons, r_config, r_hash, r_io, r_crypto, r_core, r_bin,
    libr_shlr
  ],
  dependencies: [r_magic],
  install: true,
  implicit_include_directories: false
)
