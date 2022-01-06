const r2pipe = require("r2pipe");
const r2 = r2pipe.open()

console.log("jo")
r2.cmd("aa");
var res = r2.cmdj("aflj");
console.log(res);
console.log("done")
