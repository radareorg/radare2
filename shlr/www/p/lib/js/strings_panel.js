// STRINGS PANEL
var StringsPanel = function () {

};

StringsPanel.prototype.render = function() {
	$('#strings_tab').html('<div id="strings" style="color:rgb(127,127,127);"></div>');
	r2.cmdj("izj", function(strings) {
	  var data = [];
	    for (var i in strings) {
	      var f = strings[i];
	      var fd = {
	        label: f.string,
	        children: [
	          {label: "vaddr: " + "0x" + f.vaddr.toString(16)},
	          {label: "paddr: " + "0x" + f.paddr.toString(16)},
	          {label: "length: " + f.length},
	          {label: "type: " + f.type}
	        ]
	      };
	      data[data.length] = fd;
	    }
	    $('#strings').tree({data: [],selectable: false,slide: false,useContextMenu: false});
	    $('#strings').tree('loadData', data);
	});
};

