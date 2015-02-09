// HEXDUMP PANEL
var HexPanel = function () {
	this.min = 0;
	this.max = 0;
	this.block = 1024;
	this.base = "entry0";
};

HexPanel.prototype.seek = function(addr, scroll) {
	this.base = addr;
	this.min = this.max = 0;
	r2.cmd (inColor("px " + this.block + "@" + addr), function (x) {
	  x = render_hexdump(x);
	  $("#hex_tab").html("<div style='overflow: scroll;padding-left: 30px;'><pre id='hexdump' style='color:rgb(127,127,127);''>" + x + "</pre></div>");
	});
};
HexPanel.prototype.scrollTo = function(x,y) {
};

function render_hexdump(x) {
	var html = "";
	var lines = x.split('\n');
	for (var i in lines) {
		var line = lines[i];
		html += "<div>" + line + "</div>";
	}
	return html;
};