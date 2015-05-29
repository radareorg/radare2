// STRINGS PANEL
var StringsPanel = function () {

};

StringsPanel.prototype.render = function() {
	$('#strings_tab').html('<div id="strings" style="color:rgb(127,127,127);"></div>');
	//Added String search bar and length bar
	$('#strings').before('<div class="ui-toolbar ui-widget-header ui-helper-clearfix" style="padding:5px;"><input id="search_string" type="text" placeholder="Search "><input id="string_length" type="text" placeholder="Length" style="margin-left:50px;"></div>');
	r2.cmdj("izj", function(strings) {
		var data = [];
		for (var i in strings) {
			var f = strings[i];
			var fd = {
				offset: f.paddr,
				label: atob(f.string),
				children: [
				{label: "vaddr: " + "0x" + f.vaddr.toString(16)},
				{label: "paddr: " + "0x" + f.paddr.toString(16)},
				{label: "length: " + f.length},
				{label: "type: " + f.type}
				]
			};
			data[data.length] = fd;
		}
	    data = data.sort(function(a,b) {return a.offset - b.offset;});
	    $('#strings').tree({data: [],selectable: false,slide: false,useContextMenu: false});
	    $('#strings').tree('loadData', data);
	});
	// Searched for all the occurence of the substring in the string
	$( "#search_string" ).change(function() {
		str=$('#search_string').val();
		if(str.length==0)
			StringsPanel.prototype.render();
		else
		{
			r2.cmdj("izj", function(strings) {
				var data = [];
				for (var i in strings) {
					var f = strings[i];
	    			str.toLowerCase();
	    			str1=atob(f.string).slice(0,-1)
	    			str1.toLowerCase();
	    			// Searches all the occurence of the string with fixed length
	    			if($('#string_length').val())
	    			{
	    				len=$('#string_length').val();
						if(str1.indexOf(str)>=0 && f.length==len)
						{ 
							var fd = {
								offset: f.paddr,
								label: atob(f.string),
								children: [
								{label: "vaddr: " + "0x" + f.vaddr.toString(16)},
								{label: "paddr: " + "0x" + f.paddr.toString(16)},
								{label: "length: " + f.length},
								{label: "type: " + f.type}
								]
							};
							data[data.length] = fd;
						}
					}
					else{
						if(str1.indexOf(str)>=0)
						{ 
							var fd = {
								offset: f.paddr,
								label: atob(f.string),
								children: [
								{label: "vaddr: " + "0x" + f.vaddr.toString(16)},
								{label: "paddr: " + "0x" + f.paddr.toString(16)},
								{label: "length: " + f.length},
								{label: "type: " + f.type}
								]
							};
							data[data.length] = fd;
						}
					}
				}
	   	data = data.sort(function(a,b) {return a.offset - b.offset;});
	   	$('#strings').tree({data: [],selectable: false,slide: false,useContextMenu: false});
	    $('#strings').tree('loadData', data);
	});
}
});
// Filtering strings by the string length
$('#string_length').change(function(){
	if($('#string_length').val()==0 || $('#string_length').val()=='undefined' )
		StringsPanel.prototype.render();
	else{
		r2.cmdj("izj", function(strings) {
			var data = [];
			for (var i in strings) {
				var f = strings[i];
	    		str=$('#search_string').val();
	    		str.toLowerCase();
	    		str1=atob(f.string).slice(0,-1)
	    		str1.toLowerCase();
	    		if(str.length>0 && $('#string_length').val())
	    		{
	     				len=$('#string_length').val();
	     				if(f.length==len && str1.indexOf(str)>=0)
	     				{ 
	     					var fd = {
	     						offset: f.paddr,
	     						label: atob(f.string),
	     						children: [
	     						{label: "vaddr: " + "0x" + f.vaddr.toString(16)},
	     						{label: "paddr: " + "0x" + f.paddr.toString(16)},
	     						{label: "length: " + f.length},
	     						{label: "type: " + f.type}
	     						]
	     					};
	     					data[data.length] = fd;
	     				}
	     			}
	     			else
	     			{
	     				len=$('#string_length').val();
	      				if(f.length==len)
	      				{ 
	      					var fd = {
	      						offset: f.paddr,
	      						label: atob(f.string),
	      						children: [
	      						{label: "vaddr: " + "0x" + f.vaddr.toString(16)},
	      						{label: "paddr: " + "0x" + f.paddr.toString(16)},
	      						{label: "length: " + f.length},
	      						{label: "type: " + f.type}
	      						]
	      					};
	      					data[data.length] = fd;
	      				}
	      			}
	      		}
	      		data = data.sort(function(a,b) {return a.offset - b.offset;});
	      		$('#strings').tree({data: [],selectable: false,slide: false,useContextMenu: false});
	      		$('#strings').tree('loadData', data);
	      	});
}
});
};

