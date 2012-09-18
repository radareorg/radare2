var r2 = require ('../r_core');

var core = new r2.RCore();


console.log ("ptr " , core._pointer);
console.log ("bin " , core.bin._pointer);
console.log ("cfg " , core.config._pointer);
console.log ("bsz " , core.offset._pointer);
console.log ("off " , core.blocksize._pointer);
console.log (core.config);
console.log ((null == core.config.get("io.va"))?"fail":"works!")
	
