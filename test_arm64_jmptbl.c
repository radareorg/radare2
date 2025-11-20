/* Test case for ARM64 jump table detection issue */
#include <r_anal.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_io.h>
#include <r_cons.h>

static int test_arm64_jmptbl(void) {
    RAnal *anal = r_anal_new ();
    r_anal_use (anal, "arm64");
    
    // Create a mock IO with the ARM64 jump table pattern
    RIO *io = r_io_new ();
    // This would need to be populated with the actual bytes from the sample
    
    r_anal_bind (anal, io);
    
    // Test the jump table detection
    // This would require setting up the function and basic blocks properly
    
    r_anal_free (anal);
    r_io_free (io);
    return 1;
}

int main() {
    return test_arm64_jmptbl();
}