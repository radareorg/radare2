//Get the context of the canvas element we want to select
var ctx = document.getElementById("myChart").getContext("2d");
/*
var data = {
	labels : ["January","February","March","April","May","June","July"],
	datasets : [
		{
			fillColor : "rgba(220,220,220,0.5)",
			strokeColor : "rgba(220,220,220,1)",
			pointColor : "rgba(220,220,220,1)",
			pointStrokeColor : "#fff",
			data : [65,59,90,81,56,55,40]
		},
		{
			fillColor : "rgba(151,187,205,0.5)",
			strokeColor : "rgba(151,187,205,1)",
			pointColor : "rgba(151,187,205,1)",
			pointStrokeColor : "#fff",
			data : [28,48,40,19,96,27,100]
		}
	]
}
*/
var options = {
	scaleOverlay : true,
	scaleOverride : true,
	scaleSteps : 15,
	scaleStepWidth : 1,
	scaleStartValue : 0,
	scaleLineColor : "rgba(0,0,0,.1)",
	scaleLineWidth : 1,
	scaleShowLabels : false,
	scaleLabel : "<%=value%>",
	scaleFontFamily : "'Arial'",
	scaleFontSize : 12,
	scaleFontStyle : "normal",
	scaleFontColor : "#666",	
	scaleShowGridLines : true,
	scaleGridLineColor : "rgba(0,0,0,.05)",
	scaleGridLineWidth : 1,	
	bezierCurve : true,
	pointDot : false,
	pointDotRadius : 3,
	pointDotStrokeWidth : 1,
	datasetStroke : true,
	datasetStrokeWidth : 2,
	datasetFill : true,
	animation : true,
	animationSteps : 90,
	animationEasing : "easeOutQuart",
	onAnimationComplete : null
}

//new Chart(ctx).Line(data,options);
new Chart(ctx).Radar(data,options);
