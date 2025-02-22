project('binaryninja', 'c', meson_version : '>=0.60.0', version : '2.0.2')

sources_arm64 = [
  'arch/arm64/disassembler/decode.c',
  'arch/arm64/disassembler/decode0.c',
  'arch/arm64/disassembler/decode1.c',
  'arch/arm64/disassembler/decode2.c',
  'arch/arm64/disassembler/decode_fields32.c',
  'arch/arm64/disassembler/decode_scratchpad.c',
  'arch/arm64/disassembler/encodings_dec.c',
  'arch/arm64/disassembler/encodings_fmt.c',
  'arch/arm64/disassembler/format.c',
  'arch/arm64/disassembler/gofer.c',
  'arch/arm64/disassembler/operations.c',
  'arch/arm64/disassembler/pcode.c',
  'arch/arm64/disassembler/regs.c',
  'arch/arm64/disassembler/sysregs.c'
]

incs_arm64 = include_directories(['arch/arm64/disassembler'])
libs_arm64 = both_libraries('v35arm64', sources_arm64)

sources_armv7 = [
  'arch/armv7/armv7_disasm/armv7.c',
]

incs_armv7 = include_directories(['arch/armv7/armv7_disasm'])
libs_armv7 = both_libraries('v35armv7', sources_armv7)

# v35arm64_dep = declare_dependency(
#   link_with: [libs.get_static_lib()],
#   include_directories: incs
# )

