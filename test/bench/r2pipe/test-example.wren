

System.print("Hello World")
var a = R2.cmd("?E hello world;aaa")

var json_length = R2.cmd("aflj").count
System.print("input json length = " + json_length.toString)
var obj = R2.cmdj("aflj")
System.print("contains = " + obj.count.toString + " entries")

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
