
# project('ptrace-wrap', 'c')

thread_dep = dependency('threads')

ptrace_wrap_inc = include_directories('include')

ptrace_wrap_src = ['src/ptrace_wrap.c']

ptrace_wrap_lib = static_library('ptrace_wrap',
                          ptrace_wrap_src,
                          include_directories: ptrace_wrap_inc,
                          dependencies: thread_dep)

ptrace_wrap_dep = declare_dependency(link_with: ptrace_wrap_lib, include_directories: ptrace_wrap_inc)

# subdir('test')
