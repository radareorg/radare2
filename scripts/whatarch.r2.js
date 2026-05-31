const architectures = [
    {arch: "arm", bits: [64, 32, 16]},
    {arch: "x86", bits: [64, 32, 16]},
    {arch: "mips", bits: [64, 32, 16]},
    {arch: "ppc", bits: [64, 32]}
];

let bestMatch = {arch: "", bits: 0, invalidCount: Infinity};

for (const config of architectures) {
    for (const bit of config.bits) {
        // Set architecture and bit width
        r2.cmd(`e asm.arch=${config.arch}`);
        r2.cmd(`e asm.bits=${bit}`);
        
        // Perform a short disassembly
        const disasm = r2.cmdj('pdj 80');
        let invalidCount = 0;

        // Count invalid instructions
        disasm.forEach(instruction => {
            if (instruction.opcode === 'invalid') {
                invalidCount++;
            }
        });

        console.log(`Testing ${config.arch}-${bit}: ${invalidCount} invalid instructions`);

        // Track the best configuration
        if (invalidCount < bestMatch.invalidCount) {
            bestMatch = {arch: config.arch, bits: bit, invalidCount};
        }
    }
}

console.log(`Best match: ${bestMatch.arch}-${bestMatch.bits}`);

// Set the best configuration
r2.cmd(`e asm.arch=${bestMatch.arch}`);
r2.cmd(`e asm.bits=${bestMatch.bits}`);
