var r2 = require ('../r_core');

var core = new r2.RCore();

console.log (core.config);
console.log ((null == core.config.get("io.va"))?"fail":"works!")
	
