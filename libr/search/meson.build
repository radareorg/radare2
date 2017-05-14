files=[
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

r_search = shared_library('r_search', files,
  include_directories: include_directories([
  '../include'],
  platform_librinc
  ),
  link_with: [r_util],
  install: true
)
