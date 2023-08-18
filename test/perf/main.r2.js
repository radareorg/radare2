/// r2 performance testsuite ///

// console.log('Running the benchmark testsuite for radare2')

function parseLogs() {
	const logFiles = r2.cmd('ls -q')
		.trim().split(/\n/g)
		.filter((x) => !x.startsWith('.') && x.endsWith('.json'))
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
				o[count] = { commit: commit, count: count, tests: {} };
				o[count].tests[name] = [test];
			}
			// console.log(test.time_elapsed, '\t', test.name);
		}
	}
	const logs = [];
	const keys = Object.keys (o).sort((x)=> {
		return (+x.count) - (+this.count);
	});
	for (const kount of keys) {
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
		log.diff = 0 | (log.total - logs[i - 1].total);
	}
	logs.reverse();
	return logs;
}

const logs = parseLogs();
console.log("<html>");
console.log('<script src="https://d3js.org/d3.v3.min.js"></script>');
console.log('<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.9.4/Chart.js"></script>');


console.log("<body style='link:red;background-color:white;color:black;font-weight:bold;font-family:Verdana;font-size:1em'>");
console.log("<h1>Radare2 Benchmark</h1>\n");
console.log("<h3>Lower is Better</h3>\n");
// console.log(JSON.stringify(logs, null, 2));
console.log('<div style="position:absolute;right:0">');
console.log('<canvas id="myChart" style="width:100%;max-width:600px"></canvas>');
console.log('<canvas id="myChart2" style="width:100%;max-width:600px"></canvas>');
console.log('</div>');
const totals = logs.map((x) => x.total);
const yvalues = '['+totals.reverse().join(',')+']';
const averages = logs.map((x) => (11)*x.average);
const avalues = '['+averages.reverse().join(',')+']';
const xvalues = '[' + logs.map((x) => x.count).reverse().join(',')+']';
let datasets = '';
function getdata(log, two, log2) {
	if (!log) {
		return [];
	}
	const keys = Object.keys(log.tests).sort();
	const ret = [];
	const o = {};
	for (let key of keys) {
		const t = log.tests[key];
		for (const tt of t) {
			if (o[key]) {
				o[key] += tt.time_elapsed;
				o[key] /= 2;
			} else {
				o[key] = tt.time_elapsed;
			}
		}
	}
	const log2data = (two && log2)? getdata(log2): [];
	for (let k = 0 ; k < keys.length; k++) {
		const key = keys[k];
		const num = 0 | (o[key] / 1000);
		if (two) {
			const dk = log2data[k];
			//console.log(dk, num, "<br>");
			const kolor = (dk > num)?"80ff80": "#ff8080";
			ret.push('<td style="background-color:'+kolor+'" title='+key+'>'+num+'</td>');
		} else {
			ret.push(num);
		}
	}
	return ret;
}

function getName(d) {
	return logs[d].commit;
}
const res = {};
for (const kount of Object.keys(logs)) {
	const log = logs[kount];
	const data = getdata(log);
	for (const d of Object.keys(data)) {
		if (res[d]) {
			res[d].data.push(data[d]);
		} else {
			res[d] = {name: getName(kount), data : [data[d]]};
		}
	}
}
let ares = [];
for (const r of Object.keys(res)) {
	res[r].data = res[r].data.reverse();
	ares.push(res[r]);
}
ares.sort((x) => x.count - this.count);

for (const are of ares) {
	const r = 0|(Math.random()*255);
	const g = 0|(Math.random()*255);
	const b = 0|(Math.random()*255);
	let ds = `
	datasets.push({
	      label: "'${are.name}'",
	      fill: false,
	      backgroundColor:"rgba(${r},${g},${b},0.4)",
	      borderColor:"rgba(${r},${g},${b},0.8)",
	      data: [ ${are.data} ]
	    });
	`;
	datasets += ds;
}
const msg = `
<script>
const xValues = ${xvalues};
// const yValues = [7,8,8,9,9,9,10,11,14,14,15];
const yValues = ${yvalues};
const aValues = ${avalues};
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
const datasets = [];
${datasets}
new Chart("myChart2", {
  type: "line",
  data: {
    labels: xValues,
    datasets: datasets
  },
  options:{}
});
</script>
`;
console.log(msg);

console.log("<table style='background-color:#a0a0a0;color:black' border=1>");
let line = "<tr style='background-color:#404040;color:white'>\n  ";
line += "<td>label</td>";
line += "<td>count</td>";
// line += "<td>commit</td>";
line += "<td>diff</td>";
line += "<td>total</td>";
line += "<td>average</td>";
line += "<td>tests</td>";
line += "</tr>";
console.log(line);
function gettitle(log, i) {
	return Object.keys(log.tests).sort()[i];
}
// todo add log.diff computing it with the aveage
const logKeys = Object.keys(logs).sort((x) => x - this);
for (let n = 0; n < logKeys.length; n++) {
	const kount = logKeys[n];
	const log = logs[kount];
	const log2 = logs[logKeys[n + 1]];
	// console.log(JSON.stringify(log, null, 2));
	let line = "<tr>";
	// line += "<td>"+log.count+"</td>";
	const label = log.commit.length < 10? log.commit: log.count;
	line += "<td>"+label + "</td>";
	line += "<td><a href='https://github.com/radareorg/radare2/commit/"+log.commit+"'>"+log.count+"</a></td>";
	var bg = log.diff > 10? "#ff8080": "#80ff80";
	line += "<td style='background-color:"+bg+"'>"+log.diff+"</td>";
	line += "<td>"+log.total+"</td>";
	line += "<td>"+log.average+"</td>";
	const lldata_a = getdata(log);
	const lldata_b = getdata(log2);
	const lldata = [];
	for (let i = 0; i<lldata_a.length; i++) {
		const ka = lldata_a[i] || 0;
		const kb = lldata_b[i] || 0;
		var bg = (ka <= kb)? "#80ff80": "#ff8080";
		const title = gettitle(log, i);
//		console.log(JSON.stringify(logs[kount]));
		lldata.push('<td title="'+title+'" style="background-color:'+bg+'">'+ka+'</td>\n');
	}
	line += lldata.join('');
	line += "</tr>";
	console.log(line);
}
console.log("</html>");
