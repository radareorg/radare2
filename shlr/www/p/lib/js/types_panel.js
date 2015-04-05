var TypesPanel = function () {
	this.data = [];
};

TypesPanel.prototype.insertData = function(k, v, array) {
	if(typeof array === 'undefined') { array = this.data};
	var kt = k[0].trim();
	if(k.length == 1) {
		console.log("case 1: " + array + " | " + kt + " | " + v);
		array.push({
			label: kt,
			value: v
		});
		return;
	} else if(array.length < 1) {
		console.log("case 2: " + array + " | " + kt + " | " + v);
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
				console.log("case 3: " + array + " | " + kt + " | " + v);
				this.insertData(k.slice(1), v, array[i].children);
				return;
			} else {
				console.log("case 4: " + array + " | " + kt + " | " + v);
				var obj = array[i];
				if(k.length < 2) {
					//array[i].children = [];
					return;
				} else {
				 	array[i].children = [];
				 	this.insertData(k.slice(1), v, array[i].children);
				 	return;
				}
			}
		}
	}

	//was not found in array, create it
	console.log("case 5: " + array + " | " + kt + " | " + v);
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

			console.log("inserting (k:" + k + ", v:" + v);
			ref.insertData(k, v);					 
	}
	});	
}

TypesPanel.prototype.render = function() {
	$("#types_tab").html('<div id="types" style="color:rgb(127,127,127);"></div>');

	this.data = [];
	this.generateContent();
	
	$("#types").tree({
		data: this.data,
		onCreateLi: function(node, $li) {
				if(typeof node.value !== 'undefined') {
					$li.find(".jqtree-element").append(" (" + node.value + ")");
				}
			}
	});
}