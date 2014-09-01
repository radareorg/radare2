function _(x) { return document.getElementById (x); }

var Tiled = function(id) {
	var obj = document.getElementById (id);
	this.curframe = undefined;
	this.frames = [];
	var topmargin = 20;
	var w = 3;
	var h = 0;
	this.update_size = function (width, height) {
		w = width || window.innerWidth;
		h = height || window.innerHeight;
	}
	this.max_width = function (set) {
		var col = this.curframe[1];
		for (var col in this.frames) {
			for (var row in this.frames[col]) {
				this.frames[col][row].mw = false;
			}
		}
		this.curframe[0].mw = set;
	}
	this.max_height = function (set) {
		if (this.curframe) {
			var col = this.curframe[1];
			for (var row in this.frames[col]) {
				var f = this.frames[col][row];
				f.mh = false;
			}
			this.curframe[0].mh = set;
		}
	}
this.ctr2 = 0;
	this.tile = function () {
		if (this.maximize && this.curframe) {
			var mtop = topmargin;
			var left = 0;
			var width = w;
			var height = h-mtop;

			var f = this.curframe[0];
			f.obj.style.position = 'absolute';
			f.obj.style.top = mtop;
			f.obj.style.left = left;
// always on top.. or hide all the frames
f.obj.style.zIndex = 99999+this.ctr2++;
			// TODO: add proportions
			f.obj.style.width = width;
			f.obj.style.height = height;
			//f.obj.style.backgroundColor = "green";
//f.obj.innerHTML =" FUCK";
			if (f.update)
				f.update (f.obj);
			return;
		}
			function getmaxh (self,col) {
				if (self.frames[col]) {
					for (var row in self.frames[col]) {
						var f = self.frames[col][row];
						if (f && (f.mh||f.selected))
							return true;
					}
				}
				return false;
			}
			function getmaxw () {
				for (var col in this.frames) {
					for (var row in this.frames[col]) {
						var f = this.frames[col][row];
						if (f && f.mw) return true;
					}
				}
				return false;
			}
		var cols = this.frames.length;
		var left = 0;
		var hasmaxw = true; //getmaxw ();
		for (var col in this.frames) {
			var rows = this.frames[col].length;
			var mtop = topmargin;
			var cols = this.frames.length;
			var hasmaxh = getmaxh (this, col);

			var width = w/cols;
			var height = (h-topmargin)/rows;

			if (this.curframe && hasmaxw && this.frames.length>1) {
				if (col==this.curframe[1]) {
					width = w/2;
				} else {
					width = (w/2)/(cols-1);
				}
			}
			for (var row in this.frames[col]) {
				var f = this.frames[col][row];
				if (hasmaxh && this.frames[col].length>1) {
					if (f.selected) {
						height = 1.7* ((h-topmargin)/(rows));
					} else {
						var a = 1.7*(h-topmargin)/(rows);
						height = (h-a)/(rows-1);
					}
				} else {
					height = (h-topmargin)/rows;
				}
				f.obj.style.position = 'absolute';
				f.obj.style.top = mtop;
				f.obj.style.left = left;
				// TODO: add proportions
				f.obj.style.width = width;
				f.obj.style.height = height;
				//f.obj.style.backgroundColor = "green";
				if (f.update)
					f.update (f.obj);
				mtop += height;
			}
			left += width;
		};
	}

	this.num = 0;
	this.defname = function (name) {
		name = name || "noname";
		this.num++;
		return name+"_"+this.num;
	}

	this.unselect_frames = function (name) {
		for (var col in this.frames) {
			for (var row in this.frames[col]) {
				var f = this.frames[col][row];
				f.selected = false;
			}
		}
	}
	this.move_frame = function (dir) {
		if (!this.curframe)
			return;
		var col = this.curframe[1];
		switch (dir) {
		case 'up':
			// move to new column
			break;
		case 'down':
			// remove from column
			// remove column if empty
			// append to previous column
			break;
		case 'right':
			if (col==this.frames.length-1)
				return false;
			alert ("moveright Col is "+col);
			// AAAA B C DDD
			var b, c, d;
			b = this.frames[col];
			c = this.frames.splice (col);
			d = c.splice (1).slice (1);
		alert ("AAAA "+this.frames.length);
		alert ("C "+c.length);
		alert ("D "+d.length);
			if (b) this.frames.push (b);
			if (c.length>0) {
				alert ("SET COL "+this.frames.length);
				this.frames.push (c);
			}
			for (var i = 0; i<d.length; i++)
				this.frames.push (d[i]);
			this.tile ();
			break;
		case 'left':
			break;
		}
	}

	this.other_frame = function (dir) {
		if (!this.curframe)
			return;
		switch (dir) {
		case 'up':
			var col = +this.curframe[1];
			var row = +this.curframe[2];
			if (row>0) {
				row--;
				var f = this.frames[col][row];
				this.select_frame (f.name);
				this.curframe = [f,col,row];
				this.run();
			}
			break;
		case 'down':
			var col = +this.curframe[1];
			var row = +this.curframe[2];
			if (row<=this.frames[col].length) {
				row++;
				var f = this.frames[col][row];
				this.select_frame (f.name);
				this.curframe = [f,col,row];
				this.run();
			}
			break;
		case 'left':
			var col = +this.curframe[1];
			if (col>0) {
				col--;
				var f = this.frames[col][0];
				this.select_frame (f.name);
				this.curframe = [f,col,0];
				this.run();
			}
			break;
		case 'right':
			var col = +this.curframe[1];
			if (col<this.frames.length) {
				col++;
				var f = this.frames[col][0];
				this.select_frame (f.name);
				this.curframe = [f,col,0];
				this.run();
			}
			break;
		}
	}

	this.select_frame = function (name) {
		var ret = undefined;
		if (!name && this.curframe) {
			name = this.curframe[0].name;
		}
		this.oldframe = this.curframe;
		for (var col in this.frames) {
			for (var row in this.frames[col]) {
				var f = this.frames[col][row];
				if (f.name === name) {
					_('frame_'+f.name).style.backgroundColor = "black";
					f.selected = true;
f.mw = true;
					ret = this.curframe = [f,col,row];
				} else {
					_('frame_'+f.name).style.backgroundColor = "#c0c0c0";
f.mw = false;
					f.selected = false;
				}
			}
		}
		this.tile ();
		return ret;
	}
	this.new_frame = function(name, body, update, pos, cb) {
		var nf = {};
		nf.name = name = name || this.defname ();
			var obj_title = document.createElement ('div');
			obj_title.className = 'frame_title';
			obj_title.id = 'frame_'+name;
			var d = document.createElement ('div');
			d.style.backgroundColor = '#d0a090';

			var b2 = document.createElement ('a');
			b2.innerHTML = "[r]";
			b2.href='#';
			b2.ival = null;
			b2.onclick = function (x) {
				// TODO : toggle auto refresh
				if (b2.ival) {
					clearInterval (b2.ival);
					b2.ival = null;
					b2.innerHTML = "[r]";
				} else {
					b2.innerHTML = "[R]";
					if (cb) {
						cb (this);
						b2.ival = setInterval (function () {
							cb (this);
						}, 1000);
					}
				}
			}
			d.appendChild (b2);

			var b = document.createElement ('a');
			b.innerHTML = "[@] ";
			b.href='#';
			b.onclick = function (x) {
				if (cb) {
					cb (this);
				}
			}
			d.appendChild (b);

			var a = document.createElement ('a');
			a.innerHTML = name;
			a.href='#';
			d.appendChild (a);

			obj_title.appendChild (d);
			(function (self,name) {
				 a.onclick = function() {
					 //alert ("clicked "+name);
					 self.del_frame (name);
				 }
			})(this,name);
		if (typeof (update) === 'string') {
			pos = update;
			update = undefined;
		}
		nf.update = update;
		nf.obj = document.createElement ('div');
		var title = obj_title.outerHTML;
		nf.obj.className='frame';
		nf.obj.id = nf.name;
		nf.obj.appendChild (obj_title);
		var x= document.createElement ('p');
		x.innerHTML = body;
		nf.obj.appendChild (obj_title);
		nf.obj.appendChild (x);
		obj.appendChild (nf.obj);
		switch (pos) {
		case "bottom":
			// TODO: append right above the selected row
			var cc = this.curframe? this.curframe[1]: 0;
			this.frames.push ([nf]);
			this.frames[cc].push (this.frames.pop ()[0]);
			break;
		case "right":
			var col = this.curframe? this.curframe[1]: 0;
			var a = this.frames.slice (0, col+1);
			var b = this.frames.slice (col+1);
			a.push ([nf]);
			this.frames = a.concat (b);
			break;
		default:
			this.frames.push ([nf]);
			break;
		}
		this.select_frame (name);
		if (cb) {
			cb (this);
		}
		(function (self, name) {
			var f = _('frame_'+name);
			f.onmouseup = function() {
				var f = self.select_frame (name);
				if (f) {
	//				f[0].obj.innerHTML = f[0].obj.innerHTML+"<br />"; //"pop";
					//alert (f[0].obj.style.backgroundColor);
				} else alert ("Cant find frame for "+name);
			}
		})(this, name);
		return nf;
	}
	this.del_frame = function (name) {
		var prev = undefined;
		if (!name && this.curframe) {
			name = this.curframe[0].name;
		}
		for (var col in this.frames) {
			for (var row in this.frames[col]) {
				var x = this.frames[col][row];
				if (x.name==name) { 
					if (x != this.curframe[0])
						return;
					if (this.curframe[0] != this.oldframe[0])
						return;
					if (this.frames[col].length>1) {
						// remove row
						var a = this.frames[col].splice (row).slice (1);
						for (var i = 0;i<a.length;i++)
							this.frames[col].push (a[i]);
					} else {
						// remove column
						var a = this.frames.splice (col).slice (1);
						for (var i = 0; i<a.length; i++)
							this.frames.push (a[i]);
					}
					obj.removeChild (x.obj);
					if (!prev) {
						for (var col in this.frames) {
							for (var row in this.frames[col]) {
								prev = this.frames[col][row]
								break;
							}
						}
						// select next frame
					}
					this.select_frame (prev);
					//this.tile ();
					return x;
				}
				prev = x.name;
			}
		}
		this.tile ();
	}
	this.run = function () {
		this.update_size ();
		obj.style.position = 'absolute';
		obj.style.top = 0;
		obj.style.left = 0;
		obj.style.width = w;
		obj.style.height = h;
		obj.style.backgroundColor = '#a0a0a0';
		this.tile ();
	}
}
