// ENTROPY PANEL
var EntropyPanel = function () {

};

EntropyPanel.prototype.render = function() {
	var table = "<table id='entropy_chart'>";
	r2.cmd("p=", function(x) {
		var blocks = x.split('\n');
		for (var i in blocks) {
			var block = blocks[i];
			var idx = block.split(' ')[0];
			var value = parseInt(block.split(' ')[1],16);
			if (value > 0) {
				table += "<tr><td>" + idx + "</td><td>" + value + "</td></tr>";
			}
		}
	});
	table += "</table>";
	$("#entropy_tab").html("<pre id='hexdump' style='color:rgb(127,127,127);''>" + table + "</pre>");
	$("#entropy_chart").horizontalTableGraph();
};

jQuery.fn.horizontalTableGraph = function() {
    $(this).find("thead").remove();
    var maxvalue = 0;
    $(this).find("tr").each(function(i) {
    	$(this).removeClass();
    	$(this).find("td").eq(0).animate({width : '50px'}, 1000);
    	$(this).find("td").eq(1).animate({width : '500px'}, 1000).css("text-align","left");
    	$(this).find("td").eq(1).css("width","500px");
    	var getvalue = $(this).find("td").eq(1).html();
    	maxvalue = Math.max(maxvalue,getvalue);
    });
    $(this).find("tr").each(function(i) {
	    var thevalue = $(this).find("td").eq(1).html();
	    var newBar = $("<span>").html(thevalue);
	    newBar.css({
	          "display": "block",
	          "width": "0px",
	          "backgroundColor": "#600",
	          "marginBottom": "0px",
	          "padding": "0px",
	          "color": "#FFF"
        });
        $(this).find("td").eq(1).html(newBar);
        newBar.animate({"width": (100 * thevalue / maxvalue) + "%"}, "slow");
    })
};