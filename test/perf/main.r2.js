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
		let average = 0|0;
		let total = 0|0;
		for (let k of Object.keys(run.tests)) {
			const tests = run.tests[k];
			for (const t of tests) { // run.tests[k]) {
				total += 0 | (t.time_elapsed / 1000);
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
			average: 0|(average / 1000),
			tests: run.tests
		});
	}
	logs.sort((x)=> {
		return (+x.count) - (+this.count);
	});
	// compute diff
	for (let i = 1; i < logs.length; i++) {
		const log = logs[i];
	//	console.log(logs[i].total, '-', logs[i-1].total);
		log.diff = 0 | (log.total - logs[i-1].total);
	}
	logs.reverse();
	return logs;
}

const logs = parseLogs();
console.log("<html>");
console.log('<script src="https://d3js.org/d3.v3.min.js"></script>');
console.log('<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.9.4/Chart.js"></script>');


console.log("<body style='link:red;background-color:white;color:black;font-family:Verdana;font-size:1em'>");
console.log("<h1>Radare2 Benchmark</h1>\n");
console.log("<h3>Lower is Better</h3>\n");
// console.log(JSON.stringify(logs, null, 2));
console.log('<canvas id="myChart" style="width:100%;max-width:600px"></canvas>');
console.log('<canvas id="myChart2" style="width:100%;max-width:600px"></canvas>');
const totals = logs.map((x) => x.total);
const yvalues = '['+totals.reverse().join(',')+']';
const averages = logs.map((x) => (4.5)*x.average);
const avalues = '['+averages.reverse().join(',')+']';
const xvalues = '[' + logs.map((x) => x.count).reverse().join(',')+']';
const msg = `
<script>
const xValues = ${xvalues}; // [50,60,70,80,90,100,110,120,130,140,150];
// const yValues = [7,8,8,9,9,9,10,11,14,14,15];
const yValues = ${yvalues}; // [7,8,8,9,9,9,10,11,14,14,15];
const aValues = ${avalues}; // [7,8,8,9,9,9,10,11,14,14,15];
  new Chart("myChart", {
  type: "line",
  data: {
    labels: xValues,
    datasets: [{
      label: 'total',
      backgroundColor:"rgba(0,0,200,0.4)",
      borderColor: "rgba(0,0,250,0.8)",
      data: yValues
    },{
      label: 'average',
      backgroundColor:"rgba(0,200,0,0.4)",
      borderColor: "rgba(0,250,0,0.8)",
      data: aValues
    }]
  },
  options:{}
});
new Chart("myChart2", {
  type: "line",
  data: {
    labels: xValues,
    datasets: [{
      label: 'time',
      backgroundColor:"rgba(0,200,0,0.4)",
      borderColor: "rgba(0,250,0,0.8)",
      data: aValues
    }]
  },
  options:{}
});
</script>
`;
console.log(msg);

console.log("<table border=1>");
let line = "<tr style='background-color:#404040'>\n  ";
line += "<td>count</td>";
line += "<td>commit</td>";
line += "<td>diff</td>";
line += "<td>total</td>";
line += "<td>average</td>";
line += "<td>tests</td>";
line += "</tr>";
console.log(line);
// todo add log.diff computing it with the aveage
for (const kount of Object.keys(logs)) {
	const log = logs[kount];
	// console.log(JSON.stringify(log, null, 2));
	let line = "<tr>";
	line += "<td>"+log.count+"</td>";
	line += "<td><a href='https://github.com/radareorg/radare2/commit/"+log.commit+"'>"+log.commit+"</a></td>";
	const bg = log.diff > 0? "red": "green";
	line += "<td style='background-color:"+bg+"'>"+log.diff+"</td>";
	line += "<td>"+log.total+"</td>";
	line += "<td>"+log.average+"</td>";
	line += "<td>"+Object.keys(log.tests).join('<br />')+"</td>";
	line += "</tr>";
	console.log(line);
}
console.log("</html>");
