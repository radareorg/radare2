/* */
const ioqjsPlugin = {
	name: "qjs",
	desc: "Simple io plugin in javascript",
	license: "MIT",
	check: function (uri, perm) {
		return uri.startsWith("qjs://");
	},
	open: function (uri, perm) {
		console.log("open URI is " + uri);
		return true;
	},
	read: function (addr, len) {
		      console.log("READ");
		return [1,2,3];
	},
	seek: function (addr, whence) {
		const size = 32; // XXX custom size / resizable?
		const res = (whence === 2) ? size: addr;
		console.log("seek", addr, whence, "=", res);
		return res;
	},
	write: function () {},
	close: function () {},
}

/*
// pseudo-typescript
class IoqjsPlugin {
	#name = "qjs";
	#desc = "Simple io plugin in Typescript";
	open(fileName: string, permissions: string): bool {
		return true;
	}
}
*/

r2.plugin("io", () => ioqjsPlugin);
