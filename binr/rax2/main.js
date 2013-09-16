// connect to canvas
var Module = {
  arguments: document.location.hash.substring(1).split(' '),
  noExitRuntime: true,
  preRun: [],
  postRun: [],
  firstRun: true,
  print: (function() {
    var element = document.getElementById('output');
    element.value = ''; // clear browser cache
    return function(text) {
      text = Array.prototype.slice.call(arguments).join(' ');
      // These replacements are necessary if you render to raw HTML
      //text = text.replace(/&/g, "&amp;");
      //text = text.replace(/</g, "&lt;");
      //text = text.replace(/>/g, "&gt;");
      //text = text.replace('\n', '<br>', 'g');
      element.value += text + "\n";
      element.scrollTop = 9999999; // focus on bottom
    };
  })(),
  printErr: function(text) {
        text = Array.prototype.slice.call(arguments).join(' ');
        if (0) { // XXX disabled for safety typeof dump == 'function') {
          dump(text + '\n'); // fast, straight to the real console
        } else {
          console.log(text);
        }
        },
           //canvas: document.getElementById('canvas'),
           setStatus: function(text) {
	      if (this.firstRun) {
			var ta = _("output");
		      _("output").value = "$ rax2\n";
		      _('output').scrollTop = 99999999;
	      }
		this.firstRun = false;
          }
      };

//Module.setStatus('Downloading...');
log ("Downloading...");
function log(x) {
	_("output").value += x;
}

function _(x) { return document.getElementById(x); }

window.onload = function FocusOnInput() {
  var inp = _('input');
  inp.focus();
  inp.onkeyup = function(e){
    if(e.keyCode == 13)
      doin();
  }
}

function keyPress() {
  if(e.which == 10 || e.which == 13) doin ();
}

function doin () {
  var input=_('input');
  if (false) {
    window.location.href = "#"+input.value;
    location.reload();
  } else {
    _('output').value += "\n"+input.value+"\n";
    Module.arguments = input.value.split (' ');
    input.value = '';
    Module.run();
  }
}

function clearOutput() {
  _("output").value = "";
  _("input").focus();
}
