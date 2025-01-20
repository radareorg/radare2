# this code was brutally pasted from Rizin

project('capstone', 'c',
  version: 'next',
  meson_version: '>=0.55.0',
)

cc = meson.get_compiler('c')

if cc.has_argument('--std=gnu99')
  add_project_arguments('--std=gnu99', language: ['c'])
elif cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

cs_files = [
  'arch/Alpha/AlphaDisassembler.c',
  'arch/Alpha/AlphaInstPrinter.c',
  'arch/Alpha/AlphaMapping.c',
  'arch/Alpha/AlphaModule.c',
  'arch/AArch64/AArch64BaseInfo.c',
  'arch/AArch64/AArch64Disassembler.c',
  'arch/AArch64/AArch64DisassemblerExtension.c',
  'arch/AArch64/AArch64InstPrinter.c',
  'arch/AArch64/AArch64Mapping.c',
  'arch/AArch64/AArch64Module.c',
  'arch/ARM/ARMBaseInfo.c',
  'arch/ARM/ARMDisassembler.c',
  'arch/ARM/ARMDisassemblerExtension.c',
  'arch/ARM/ARMInstPrinter.c',
  'arch/ARM/ARMMapping.c',
  'arch/ARM/ARMModule.c',
  'arch/HPPA/HPPADisassembler.c',
  'arch/HPPA/HPPAInstPrinter.c',
  'arch/HPPA/HPPAMapping.c',
  'arch/HPPA/HPPAModule.c',
  'arch/LoongArch/LoongArchInstPrinter.c',
  'arch/LoongArch/LoongArchDisassembler.c',
  'arch/LoongArch/LoongArchMapping.c',
  'arch/LoongArch/LoongArchDisassemblerExtension.c',
  'arch/LoongArch/LoongArchModule.c',
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
  'arch/SystemZ/SystemZDisassemblerExtension.c',
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
  'arch/Xtensa/XtensaDisassembler.c',
  'arch/Xtensa/XtensaInstPrinter.c',
  'arch/Xtensa/XtensaMapping.c',
  'arch/Xtensa/XtensaModule.c',
  'cs.c',
  'Mapping.c',
  'MCInst.c',
  'MCInstrDesc.c',
  'MCInstPrinter.c',
  'MCRegisterInfo.c',
  'SStream.c',
  'utils.c',
]

capstone_includes = [include_directories('include'), include_directories('include/capstone')]

libcapstone_c_args = [
  '-DCAPSTONE_X86_ATT_DISABLE_NO',
  '-DCAPSTONE_X86_REDUCE_NO',
  '-DCAPSTONE_USE_SYS_DYN_MEM',
  '-DCAPSTONE_DIET_NO',
  '-DCAPSTONE_HAS_AARCH64',
  '-DCAPSTONE_HAS_ALPHA',
  '-DCAPSTONE_HAS_ARM',
  '-DCAPSTONE_HAS_HPPA',
  '-DCAPSTONE_HAS_LOONGARCH',
  '-DCAPSTONE_HAS_M680X',
  '-DCAPSTONE_HAS_M68K',
  '-DCAPSTONE_HAS_MIPS',
  '-DCAPSTONE_HAS_POWERPC',
  '-DCAPSTONE_HAS_SPARC',
  '-DCAPSTONE_HAS_SYSTEMZ',
  '-DCAPSTONE_HAS_TMS320C64X',
  '-DCAPSTONE_HAS_TRICORE',
  '-DCAPSTONE_HAS_X86',
  '-DCAPSTONE_HAS_XCORE',
  '-DCAPSTONE_HAS_XTENSA',
]

if meson.get_compiler('c').has_argument('-Wmaybe-uninitialized')
  libcapstone_c_args += '-Wno-maybe-uninitialized'
endif

libcapstone = library('capstone', cs_files,
  c_args: libcapstone_c_args,
  include_directories: capstone_includes,
  implicit_include_directories: false
)

capstone_dep = declare_dependency(
  link_with: libcapstone,
  include_directories: capstone_includes
)
