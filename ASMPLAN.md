 ## Revised Plan: Eliminate RAsmOp with Rename at End

 To minimize disruption to 3rd party projects and reduce the scope of changes, we'll perform the global rename of r_anal_op_* to r_arch_op_* as the final step. This allows us to work with the existing r_anal_op_*
 APIs during the transition, only renaming everything at the end when the codebase is fully migrated.

 ### Key Adjustments

 • Rename moved to end: The bulk rename happens last, after all RAsmOp elimination is complete
 • Intermediate naming: Use r_anal_op_* as the target during migration (since RArchOp == RAnalOp currently)
 • Reduced risk: 3rd party projects continue working with r_anal_op_* until the final rename
 • Cleaner commits: Separate the RAsmOp removal from the global rename

 ### Updated Implementation Steps

 4. Dependency Verification (Medium Priority)
  • Ensure arch doesn't depend on asm
  • Maintain clean separation
 5. Global Rename (Final Step) (High Priority)
  • Rename RAnalOp → RArchOp and r_anal_op_* → r_arch_op_* across libr/ and core/
  • Update includes and typedefs
  • This is the big change, done last when everything else is stable
 6. Testing & Validation (Low Priority)
  • Compile after each major step
  • Run r2r tests for regressions

 ### Completed Steps

 1. Remove RAsmOp Wrappers (High Priority)
  • Delete libr/asm/aop.c
  • Remove r_asm_op_* function declarations from libr/include/r_asm.h
 2. Replace RAsmOp Calls (High Priority)
  • Update all 79+ r_asm_op_* calls to use r_anal_op_* equivalents:
   • r_asm_op_new() → r_anal_op_new()
   • r_asm_op_free() → r_anal_op_free()
   • r_asm_op_init() → r_anal_op_init()
   • r_asm_op_fini() → r_anal_op_fini()
   • r_asm_op_get_hex() → r_hex_bin2str() (or equivalent)
   • r_asm_op_set_*() → r_anal_op_set_*() variants
 3. Update RAsm Integration (Medium Priority)
  • Modify libr/asm/asm.c to consistently use RArch sessions (ecur/dcur)
  • Replace hardcoded mininstrsize = 1 with r_arch_info(as->config, R_ARCH_INFO_MINOP_SIZE)
  • Move IO-related config to archconfig to eliminate core dependency

 ### Benefits of This Approach

 • Minimal 3rd party impact: Projects can continue using r_anal_op_* during development
 • Staged migration: Easier to review and revert individual changes
 • Reduced complexity: Work with familiar r_anal_op_* names during the bulk of the work
 • Final unification: Everything becomes r_arch_op_* at the end for consistency
