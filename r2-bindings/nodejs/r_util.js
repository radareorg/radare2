
var FFI = require("node-ffi");

/* Example using r_util api  */
var libr_util = new FFI.Library ("/usr/lib/libr_util", {
	"r_str_rwx": [ "int" , ["string"]]
});

/*
var o = libr_util.r_str_rwx("rw");
console.log ("rw = "+o);
*/
