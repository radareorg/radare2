// PROJECTS PANEL
var ProjectsPanel = function () {

};

ProjectsPanel.prototype.render = function() {
	$('#projects_tab').html('<div style="color: white;">Open Project:</div><div id="projects" style="color:rgb(127,127,127);"></div><div id="button"><br/><input id="submit" type="submit" value="Save Project" /></div>');
	r2.cmdj("Plj", function(projects) {
	    var data = [];
	    for (var i in projects) {
	      var p = projects[i];
	      var fd = {
	        label: p,
	      };
	      data[data.length] = fd;
	    }
	    $('#projects').tree({data: [],selectable: false,slide: false,useContextMenu: false});
	    $('#projects').tree('loadData', data);
	    $('#submit').on('click', function(){
	    	var project_name = prompt("Project Name:", r2.project_name);
	    	if (project_name !== "") {
	    		r2.cmd(":Ps " + project_name, function(x) {});
	    	} else {
	    		alert("Enter a valid name");
	    	}
	    	r2.project_name = project_name;
	    });
	    $('.jqtree-element').on('click', function(){
	    	var project_name = $(this)[0].firstChild.innerText;
	    	r2.cmd("Po " + project_name, function(x) {});
	    	r2.project_name = project_name;
	    	window.location.assign("./p");
	    });
	});
};

