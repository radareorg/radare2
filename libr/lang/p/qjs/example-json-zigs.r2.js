// convert json zignatures into r2 commands

function vars(a) {
	const r = [];
	for (let v of a) {
		r.push(v.kind + (v.delta>0?"+":"") + v.delta + ":" + v.name + ":" + v.type);
	}
	return r.join(' ');
}
function graph(a) {
	const k = Object.keys(a);
	const r = [];
	for (let k of Object.keys(a)) {
		r.push(k + ":"+ a[k]);
	}
	return r.join(' ');
}
const a = JSON.parse(r2.cmd("cat a.json"));
for (const e of a) {
  console.log("za ", e.name, "b", e.bytes + ":" + e.mask);
  console.log("za ", e.name, "g", graph(e.graph));
  console.log("za ", e.name, "N", e.next);
  console.log("za ", e.name, "t", e.types);
  console.log("za ", e.name, "r", e.refs.join(' '));
  console.log("za ", e.name, "x", e.xrefs.join(' '));
  console.log("za ", e.name, "v", vars(e.vars));
  console.log("za ", e.name, "h", e.hash.bbhash);
}
