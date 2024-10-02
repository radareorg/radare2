function parseGhaLogs(gha) {
	const data = [];
	var item = {};
	let r_name = "";
	let r_title = "";
	for (let r of gha.workflow_runs) {
		console.log(r.name, r.display_title);
		const a = Date.parse(r.run_started_at);
		const b = Date.parse(r.updated_at);
		const r_time = 0|((b - a) / 1000) / 60;
		//console.log("   ", 0|((b - a) / 1000) / 60);
		if (r_title === '') {
			item = {
				title: r.display_title,
				name: r.name,
				time: r_time,
			};
		} else {
			if (r.title != r_title) {
				if (item.name == 'tcc')
				data.push(item);
				item = {
					title: r.display_title,
					name: r.name,
					time: r_time,
				};
			}
		}
		r_name = r.name;
		r_title = r.display_title;
	}
	if (item.name == 'tcc') {
		data.push(item);
	}
	return data;
}
function main() {
	const gha = require("./gha.json");
	const data = parseGhaLogs(gha);
	for (const k of data) {
		console.log(k);
	}
}
main();
