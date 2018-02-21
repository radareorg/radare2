files = [
  'aes-find.c',
  'bytepat.c',
  'keyword.c',
  # 'old_xrefs.c',
  'regexp.c',
  'rsa-find.c',
  'search.c',
  'strings.c',
  'xrefs.c',
]

r_search = library('r_search', files,
  include_directories: [platform_inc],
  link_with: [r_util],
  install: true,
  implicit_include_directories: false
)
