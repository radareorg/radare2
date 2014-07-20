
window.onresize = function () {
  resizeCanvas ();
}

function resizeBlocks() {
}

function Ajax (method, uri, body, fn) {
  var x = new XMLHttpRequest ();
  x.open (method, uri, false);
  x.onreadystatechange = function (y) {
    if (x.status == 200) {
      if (fn) fn (x.responseText);
    }
  }
  x.send (body);
}

function get_graph() {
  Ajax ('GET', "/cmd/ag $$", '', function (x) {
    document.getElementById ('mainCanvas').innerHTML = x.replace (/\\l/g,"\n");
    setMenu ();
    resizeCanvas ();
    initPageObjects ();
  });
}

function onLoad() {
  get_graph ();
}

/**
 * Resizes the main canvas to the maximum visible height.
 */
function resizeCanvas() {
  var divElement = document.getElementById("mainCanvas");
  var screenHeight = window.innerHeight || document.body.offsetHeight;
  divElement.style.height = (screenHeight - 16) + "px";
}

/**
 * sets the active menu scanning for a menu item which url is a prefix 
 * of the one of the current page ignoring file extension.
 * Nice trick!
 */
function setMenu() {
  var url = document.location.href;
  // strip extension
  url = stripExtension(url);
  
  var ulElement = document.getElementById("menu");
  var links = ulElement.getElementsByTagName("A");
  var i;
  for(i = 0; i < links.length; i++) {
    if(url.indexOf(stripExtension(links[i].href)) == 0) {
      links[i].className = "active_menu";
      return;
    }
  }
}

/**
 * Strips the file extension and everything after from a url
 */
function stripExtension(url) {
  var lastDotPos = url.lastIndexOf('.');
  return (lastDotPos <= 0)? url:
    url.substring (0, lastDotPos - 1);
}
