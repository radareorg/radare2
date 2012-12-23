var r2ui = {}
r2ui.consoleExec = function () {
	var xx = document.getElementById ('consoleBody');
	if (!xx) alert ("NO CONDSOEL DBODY");
	var str = document.getElementById ('consoleEntry');
	if (str) str = str.value;
	r2.cmd (str, function (res) {
		document.getElementById ('consoleBody').innerHTML = res;
		var entry = document.getElementById ('consoleEntry');
		entry.value = "";
	});
}

