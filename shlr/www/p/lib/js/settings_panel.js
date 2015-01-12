// SETTINGS PANEL
var SettingsPanel = function () {
};

SettingsPanel.prototype.render = function() {
	var colors = '<div><h3>Colors:</h3><br/><iframe id="colors_frame" name="colors_frame" src="colors.html" width="100%" height="400px"></iframe></div><br/>';
	var settings = '<div><h3>Settings:</h3><br/>';
	settings += '<div>Test: <input id="test" type="checkbox" /></div>';
	settings += '</div><br/>';
	settings += '<div><input value="Randomize colors" type="button" onclick="r2.cmd(\'ecr\');"></div>';
	var html = settings + colors;
	$('#settings_tab').html(html);
	$('#settings_tab').css('color', "rgb(127,127,127);");
	$('input[type=checkbox]').onoff();
};
