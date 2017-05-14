
files=[
'2048.c',
'canvas.c',
'canvas_line.c',
'cons.c',
# 'dietline.c',
'editor.c',
'grep.c',
'hud.c',
'input.c',
'less.c',
'line.c',
'output.c',
'pal.c',
'pipe.c',
'rgb.c',
'utf8.c'
]

r_cons = shared_library('r_cons', files,
  include_directories: include_directories([
  '../include'],
  platform_librinc
  ),
  link_with: [r_util],
  objects: [
    r_sdb.extract_all_objects()
  ],
  install: true
)

