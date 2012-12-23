var r2 = {};

r2.root = ""; // prefix path

function Ajax (method, uri, body, fn) {
        var x = new XMLHttpRequest ();
        x.open (method, uri, false);
	x.setRequestHeader ('Accept', 'text/plain');
        x.onreadystatechange = function (y) {
		if (x.status == 200) {
			if (fn) fn (x.responseText);
		} else alert ("ajax "+x.status)
        }
        x.send (body);
}

r2.cmd = function (c, cb) {
	Ajax ('GET', r2.root+"/cmd/"+c, '', function (x) {
		if (cb) cb (x);
	});
}

r2.alive = function (cb) {
	r2.cmd ("b", function (o) {
		var ret = false;
		if (o && o.length () > 0)
			ret = true;
		if (cb) cb (o);
	});
}

r2.getLogger = function (obj) {
	if (typeof (obj) != "object")
		obj = {};
	obj.last = 0;
	obj.events = {};
	obj.interval = null;
	r2.cmd ("ll", function (x) {
		obj.last = +x;
	});
	obj.load = function (cb) {
		r2.cmd ("lj "+(obj.last+1), function (ret) {
			var json = JSON.parse (ret);
			if (cb) cb (json);
		});
	}
	obj.clear = function (cb) {
		// XXX: fix l-N
		r2.cmd ("l-", cb); //+obj.last, cb);
	}
	obj.send = function (msg, cb) {
		r2.cmd ("l "+msg, cb);
	}
	obj.refresh = function (cb) {
		obj.load (function (ret) {
			//obj.last = 0;
			for (var i = 0; i< ret.length; i++) {
				var message = ret[i];
				obj.events["message"] ({
					"id": message[0],
					"text": message[1]
				});
				if (message[0] > obj.last)
					obj.last = message[0];
			}
			if (cb) cb ();
		});
	}
	obj.autorefresh = function (n) {
		if (!n) {
			if (obj.interval)
				obj.interval.stop ();
			return;
		}
		obj.interval = setInterval (function () {
			obj.refresh (function () {
				//obj.clear ();
			});
			return true;
		}, n*1000);
	}
	obj.on = function (ev, cb) {
		obj.events[ev] = cb;
		return obj;
	}
	return obj;
}
