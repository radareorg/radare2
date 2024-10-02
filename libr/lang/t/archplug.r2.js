function archPlug() {
  return {
    name: "myarch",
    author: "pancake",
    bits: [32],
    arch: "myarch",
    decode: function(op) {
      op.mnemonic = "nop";
      op.size = 3;
      return true;
    }
  };
}

try {
  console.log("r2plugin", r2.plugin("arch", archPlug));
  r2.cmd("-a myarch");
  r2.cmd("pd 4");
} catch (e) {
  console.error(e);
}
