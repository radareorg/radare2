/// r2 performance testsuite ///

// console.log('Running the benchmark testsuite for radare2')

function parseLogs() {
	const logFiles = r2.cmd('ls -q')
		.trim().split(/\n/g)
		.filter((x) => !x.startsWith('.'))
		.sort();

	const o = {};
	for (const log of logFiles) {
		// console.log("LF", log);
		const words = log.split('-');
		const count = words[0];
		const commit = words[1];
		const tests = JSON.parse(r2.cmd('cat ' + log));
		let av = 0;
		for (const test of tests) {
			const name = test.name;
			if (count in o) {
				const av = (+o[count].average + +test.time_elapsed) / 2;
				o[count].average = av;
				if (!o[count].tests[name]) {
					o[count].tests[name] = [test];
				} else {
					o[count].tests[name].push(test);
				}
			} else {
				o[count] = { commit:commit, count: count };
				o[count].tests = {};
				o[count].tests[name] = [test];
			}
			// console.log(test.time_elapsed, '\t', test.name);
		}
	}
	const logs = [];
	for (const kount of Object.keys (o)) {
		const run = o[kount];
		let average = 0;
		let total = 0;
		for (let k of Object.keys(run.tests)) {
			const tests = run.tests[k];
			for (const t of tests) { // run.tests[k]) {
				total += t.time_elapsed;
				if (average == 0) {
					average = t.time_elapsed;
				} else {
					average = (average + t.time_elapsed) / 2;
				}
			}
		}
		logs.push({
			count: kount,
			total: total,
			commit: run.commit,
			average: average,
			tests: run.tests
		});
	}
	logs.sort((x)=> {
		return (+x.count) - (+this.count);
	});
	// compute diff
	logs.reverse();
	for (let i = 0; i + 1 < logs.length; i++) {
		const log = logs[i];
		log.diff = log.total - logs[i+1].total;
	}
	return logs;
}

const logs = parseLogs();
console.log("<html>");
console.log("<body style='background-color:black;color:white;font-family:Verdana;font-size:1em'>");
// console.log(JSON.stringify(logs, null, 2));
console.log("<table border=1>");
let line = "<tr style='background-color:#404040'>";
line += "<td>count</td>";
line += "<td>commit</td>";
line += "<td>diff</td>";
line += "<td>time</td>";
line += "<td>tests</td>";
line += "</tr>";
console.log(line);
// todo add log.diff computing it with the aveage
for (const kount of Object.keys(logs)) {
	const log = logs[kount];
	// console.log(JSON.stringify(log, null, 2));
	let line = "<tr>";
	console.log();
	line += "<td>"+log.count+"</td>";
	line += "<td>"+log.commit+"</td>";
	line += "<td>"+log.diff+"</td>";
	line += "<td>"+log.average+"</td>";
	line += "<td>"+Object.keys(log.tests).join('<br />')+"</td>";
	line += "</tr>";
	console.log(line);
}
console.log("</html>");
