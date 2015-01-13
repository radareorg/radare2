UGLY=../enyo/node_modules/.bin/uglifyjs 
# order matters
J=lib/js/jquery-1.9.0.js
J+=lib/js/jquery-ui-latest.js
J+=lib/js/jquery.onoff.js
J+=lib/js/jquery.ui-contextmenu.js
J+=lib/js/jquery.layout-latest.js
J+=lib/js/tree.jquery.js
J+=lib/js/jquery.layout.resizePaneAccordions-latest.js
J+=lib/js/jquery.scrollTo-latest.js
J+=lib/js/disasm_panel.js
J+=lib/js/entropy_panel.js
J+=lib/js/strings_panel.js
J+=lib/js/hex_panel.js
J+=lib/js/settings_panel.js
J+=lib/js/main.js

all:
	cat $(J) | $(UGLY) > index.js || cat $(J) > index.js

indent:
	jsfmt -w lib/js/*.js
