var TypesPanel = function () {
	this.data = [];
	this.optionSpacer = 300; //space in px for option buttons
};

TypesPanel.prototype.insertData = function(k, v, array) {
	if(typeof array === 'undefined') { array = this.data };
	var kt = k[0].trim();

	if(k.length == 1) {
		array.push({
			label: kt,
			id: kt,
			value: v
		});
		return;
	} else if(array.length < 1) {
		array.push({
			label: kt ,
			children: []
		});
		this.insertData(k.slice(1), v, array[0].children);
		return;
	}

	//traverse already populated array to find right spot for insertion
	for(var i in array) {
		if(array[i].hasOwnProperty("label") && array[i].label === kt) {
			if(array[i].hasOwnProperty("children")) {
				this.insertData(k.slice(1), v, array[i].children);
				return;
			} else if(k.length > 1) {
				 array[i].children = [];
				 this.insertData(k.slice(1), v, array[i].children);
				 return;
			}
		}
	}

	//was not found in array, create + traverse
	array.push({
		label: kt
	});
	if(k.length > 1) {
		array[array.length-1].children = [];
		this.insertData(k.slice(1), v, array[array.length-1].children);
	}
}

TypesPanel.prototype.generateContent = function() {
	var ref = this;
	r2.cmd("t", function(result) {
		var strings = result.split("\n");

		for(var i in strings) {
			var s = strings[i].split("=");

			if(s.length < 2)
				continue;
			
			var k = s[0].split(".");
			var v = s[1];
		
			if(k.length < 2) {
				continue;
			}

			ref.insertData(k, v);					 
	}
	});	
}

TypesPanel.prototype.render = function() {
	$("#types_tab").html('<div id="types" style="color:rgb(127,127,127); "></div>');

	this.data = [];
	this.maxstr = 0;
	this.generateContent();
	var $tree = $("#types");
	$tree.tree({
		data: this.data,
		slide: false,
		autoOpen: 0,
		useContextMenu: false, //TODO custom context menu for add/remove/edit?
		selectable: false,
		onCreateLi: function(node, $li) {
				var app = "";
				if(typeof node.value !== 'undefined') {
					app += " (" + node.value + ")";
				}
				if(node.getLevel() === 2) {
					//depth level 2 means we're dealing with an actual type
					var w = r2ui._typ.optionSpacer;
					if(node.children && node.children.length != 0) {
						w -= 5; //sub 5px to compensate for fold icon
					}

					var style = 'font-size: 80%; font-style: normal; font-family: monospace;' +
								' cursor: pointer; position: absolute; left:' + w + 'px';
					app +=  '<i class="remove" style="' + style +
						 '"' + 'data-node-name="' + node.name + '">[-]</i>';
				}
				$li.find(".jqtree-element").append(app);
			}
	});

	$tree.on("click", ".remove", 
		function(e) {
			var label = $(e.target).data('node-name');
			r2.cmd("t- " + label, function() { r2ui._typ.render(); });
		});
}