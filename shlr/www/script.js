function Ajax (method, uri, body, fn) {
        var x = new XMLHttpRequest ();
        x.open (method, uri, false);
        x.onreadystatechange = function (y) {
                if (fn) fn (x.responseText);
        }
        x.send (body);
}

function r_core_cmd_str (x, cb) {
	Ajax ("POST", "?setComment="+hwid, cmt, function (x) {
		alert (x);
		/* force refresh */
		location.reload (true);
	});
}
