project('capstone', 'c',
  version: '5.0.1',
  meson_version: '>=0.55.0',
)

cc = meson.get_compiler('c')

if cc.has_argument('--std=gnu99')
  add_project_arguments('--std=gnu99', language: ['c'])
elif cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

if host_machine.system() == 'windows'
  platform_deps = [cc.find_library('ws2_32'), cc.find_library('wininet'), cc.find_library('psapi')]
endif

cs_files = [
  'arch/AArch64/AArch64BaseInfo.c',
  'arch/AArch64/AArch64Disassembler.c',
  'arch/AArch64/AArch64InstPrinter.c',
  'arch/AArch64/AArch64Mapping.c',
  'arch/AArch64/AArch64Module.c',
  'arch/ARM/ARMDisassembler.c',
  'arch/ARM/ARMInstPrinter.c',
  'arch/ARM/ARMMapping.c',
  'arch/ARM/ARMModule.c',
  'arch/M680X/M680XDisassembler.c',
  'arch/M680X/M680XInstPrinter.c',
  'arch/M680X/M680XModule.c',
  'arch/M68K/M68KDisassembler.c',
  'arch/M68K/M68KInstPrinter.c',
  'arch/M68K/M68KModule.c',
  'arch/Mips/MipsDisassembler.c',
  'arch/Mips/MipsInstPrinter.c',
  'arch/Mips/MipsMapping.c',
  'arch/Mips/MipsModule.c',
  'arch/PowerPC/PPCDisassembler.c',
  'arch/PowerPC/PPCInstPrinter.c',
  'arch/PowerPC/PPCMapping.c',
  'arch/PowerPC/PPCModule.c',
  'arch/Sparc/SparcDisassembler.c',
  'arch/Sparc/SparcInstPrinter.c',
  'arch/Sparc/SparcMapping.c',
  'arch/Sparc/SparcModule.c',
  'arch/SystemZ/SystemZDisassembler.c',
  'arch/SystemZ/SystemZInstPrinter.c',
  'arch/SystemZ/SystemZMapping.c',
  'arch/SystemZ/SystemZMCTargetDesc.c',
  'arch/SystemZ/SystemZModule.c',
  'arch/TMS320C64x/TMS320C64xDisassembler.c',
  'arch/TMS320C64x/TMS320C64xInstPrinter.c',
  'arch/TMS320C64x/TMS320C64xMapping.c',
  'arch/TMS320C64x/TMS320C64xModule.c',
  'arch/X86/X86ATTInstPrinter.c',
  'arch/X86/X86Disassembler.c',
  'arch/X86/X86DisassemblerDecoder.c',
  'arch/X86/X86IntelInstPrinter.c',
  'arch/X86/X86Mapping.c',
  'arch/X86/X86Module.c',
  'arch/X86/X86InstPrinterCommon.c',
  'arch/XCore/XCoreDisassembler.c',
  'arch/XCore/XCoreInstPrinter.c',
  'arch/XCore/XCoreMapping.c',
  'arch/XCore/XCoreModule.c',
  'arch/TriCore/TriCoreDisassembler.c',
  'arch/TriCore/TriCoreInstPrinter.c',
  'arch/TriCore/TriCoreMapping.c',
  'arch/TriCore/TriCoreModule.c',
  'arch/BPF/BPFDisassembler.c',
  'arch/BPF/BPFInstPrinter.c',
  'arch/BPF/BPFMapping.c',
  'arch/BPF/BPFModule.c',
  'arch/EVM/EVMDisassembler.c',
  'arch/EVM/EVMInstPrinter.c',
  'arch/EVM/EVMMapping.c',
  'arch/EVM/EVMModule.c',
  'arch/X86/X86InstPrinterCommon.c',
  'arch/MOS65XX/MOS65XXDisassembler.c',
  'arch/MOS65XX/MOS65XXModule.c',
  'arch/RISCV/RISCVMapping.c',
  'arch/RISCV/RISCVModule.c',
  'arch/RISCV/RISCVInstPrinter.c',
  'arch/RISCV/RISCVDisassembler.c',
  'cs.c',
  'MCInst.c',
  'MCInstrDesc.c',
  'MCRegisterInfo.c',
  'SStream.c',
  'Mapping.c',
  'utils.c',
]

capstone_includes = [include_directories('include'), include_directories('include/capstone')]

user_plugins = get_option('plugins').split(',')
no_user_plugins = get_option('plugins') == ''
cs_c_args = [
  '-DCAPSTONE_USE_SYS_DYN_MEM',
  '-DCAPSTONE_DIET_NO',
]
if user_plugins.contains('x86') or no_user_plugins
  cs_c_args += [
    '-DCAPSTONE_HAS_X86',
    '-DCAPSTONE_X86_ATT_DISABLE_NO',
    '-DCAPSTONE_X86_REDUCE_NO',
  ]
endif
if user_plugins.contains('arm') or no_user_plugins
  cs_c_args += [
    '-DCAPSTONE_HAS_ARM',
    '-DCAPSTONE_HAS_ARM64',
  ]
endif
if user_plugins.contains('sparc') or no_user_plugins
  cs_c_args += [
    '-DCAPSTONE_HAS_SPARC',
  ]
endif
if user_plugins.contains('mips') or no_user_plugins
  cs_c_args += [
    '-DCAPSTONE_HAS_MIPS',
  ]
endif
if no_user_plugins
  cs_c_args += [
    '-DCAPSTONE_HAS_M68K',
    '-DCAPSTONE_HAS_M680X',
    '-DCAPSTONE_HAS_POWERPC',
    '-DCAPSTONE_HAS_SPARC',
    '-DCAPSTONE_HAS_SYSZ',
    '-DCAPSTONE_HAS_XCORE',
    '-DCAPSTONE_HAS_TMS320C64X',
  ]
endif

cs_c_args += [
  '-DCAPSTONE_HAS_BPF',
  '-DCAPSTONE_HAS_EVM',
  '-DCAPSTONE_HAS_MOS65XX',
  '-DCAPSTONE_HAS_RISCV',
]

libcapstone = static_library('capstone', cs_files,
  c_args: cs_c_args,
  include_directories: capstone_includes,
  implicit_include_directories: false
)

capstone_dep = declare_dependency(
  link_with: libcapstone,
  include_directories: capstone_includes
)
