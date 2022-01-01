

System.print("Hello World")
var a = R2.cmd("?E hello world;aaa")
var obj = R2.cmdj("aflj")
System.print(obj)

class R2Api {
	foo=(v) {
		//this.foo = v
	}
	construct new() {
		this.foo = 123
	}
	fileInfo() {
		return R2.cmdj("ij")
	}
}


var ra = R2Api.new()
/*

var fi = ra.fileInfo()
System.print(fi["core"])
*/
