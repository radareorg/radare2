/**
 * Autocompletion classe, define a way to build an autocompletion process
 * with a fixed set of entries.
 *
 * @param {String} formId - Literal DOM id #field
 * @param {String} choicesId - Literal DOM id #dropdown
 * @param {String} cmd - run into r2 to populate the autocompletion, eg. 'fs *;fj'
 * @param {integer} minChar - number of charcaters to start autocompletion
 * @param {integer} maxProp - maximum propositions to offer
 */
function Autocompletion(formId, choicesId, cmd, minChar, maxProp) {
	this.form_ = formId;
	this.dropdown_ = choicesId;
	this.cmd_ = cmd;
	this.minChar_ = minChar || 2;
	this.maxProp_ = maxProp || 10;
	this.init_();
}

Autocompletion.prototype.Keys = {
	UP: 38,
	DOWN: 40,
	ENTER: 13
};

Autocompletion.prototype.Nodes = {
	EMPTY: {pos: -1, offset: 0, length: 0, name: 'No match!'}
};

Autocompletion.prototype.init_ = function() {
	this.form_ = document.getElementById(this.form_);
	this.dropdown_ = document.getElementById(this.dropdown_);

	var boundKeyUpHandler = this.keyHandler.bind(this);
	this.form_.addEventListener('keyup', boundKeyUpHandler);

	var _this = this;
	this.form_.addEventListener('focus', function() {
		if (_this.prevLength_ >= _this.minChar_) {
			_this.show();
		}
	});

	this.form_.addEventListener('blur', function() {
		_this.hide();
	});

	this.flags_ = undefined;
	this.activeChoice_ = 0;
	this.prevLength_ = 0;
	this.list_;
	this.completions_;

	this.populate_();
};

Autocompletion.prototype.populate_ = function() {
	var _this = this;
	r2.cmdj(this.cmd_, function(f) {
		_this.flags_ = f;
	});
};

Autocompletion.prototype.process_ = function(str) {
	var selectedFlags = [];

	var howMany = 0;
	for (var i = 0 ; i < this.flags_.length ; i++) {
		var offset = this.flags_[i].name.indexOf(str, 0);
		if (offset !== -1) {
			selectedFlags.push({
				pos: howMany++,
				offset: offset,
				length: str.length,
				name: this.flags_[i].name
			});
		}

		if (howMany == this.maxProp_) {
			return selectedFlags;
		}
	}
	return selectedFlags;
};

Autocompletion.prototype.addNode_ = function(item, active) {
	var node = document.createElement('li');
	if (active) {
		node.className = 'active';
	}

	var _this = this;

	node.addEventListener('mouseover', (function(pos) {
		return function() {
			_this.setActiveChoice(pos);
		};
	})(item.pos));

	node.addEventListener('mousedown', (function(pos) {
		return function() {
			_this.setActiveChoice(pos);
			_this.valid();
		};
	})(item.pos));

	var emphasis = document.createElement('strong');
	emphasis.appendChild(document.createTextNode(item.name.substr(item.offset, item.length)));

	node.appendChild(
		document.createTextNode(
			item.name.substr(0, item.offset)));
	node.appendChild(emphasis);
	node.appendChild(
		document.createTextNode(
			item.name.substr(item.offset + item.length, item.name.length - (item.offset + item.length))));
	this.dropdown_.appendChild(node);
};

Autocompletion.prototype.cleanChoices_ = function() {
	// Cleaning old completion
	while (this.dropdown_.firstChild) {
		this.dropdown_.removeChild(this.dropdown_.firstChild);
	}
};

Autocompletion.prototype.setActiveChoice = function(newActive) {
	for (i in this.dropdown_.childNodes) {
		if (i == newActive) {
			this.dropdown_.childNodes[i].className = 'active';
		} else if (i == this.activeChoice_) {
			this.dropdown_.childNodes[i].className = '';
		}
	}
	this.activeChoice_ = newActive;
};

Autocompletion.prototype.keyMovement_ = function(key) {
	if (key == this.Keys.UP && this.activeChoice_ > 0) {
		console.log('UP');
		this.setActiveChoice(this.activeChoice_ - 1);
	}

	if (key == this.Keys.DOWN && this.activeChoice_ < this.dropdown_.childNodes.length - 1) {
		console.log('DOWN');
		this.setActiveChoice(this.activeChoice_ + 1);
	}
};

Autocompletion.prototype.valid = function() {
	if (this.activeChoice_ == -1 || this.dropdown_.childNodes.length <= this.activeChoice_) {
		return;
	}
	this.form_.blur();
	this.prepareView();
	return seek(this.completions_[this.activeChoice_].name);
};

Autocompletion.prototype.show = function() {
	this.dropdown_.style.display = 'block';
};

Autocompletion.prototype.hide = function() {
	this.dropdown_.style.display = 'none';
};

Autocompletion.prototype.keyHandler = function(e) {
	if (e.keyCode == this.Keys.UP || e.keyCode == this.Keys.DOWN) {
		return this.keyMovement_(e.keyCode);
	}

	if (e.keyCode == this.Keys.ENTER) {
		this.hide();
		return this.valid();
	}

	var value = e.target.value;
	this.cleanChoices_();

	if (value.length >= 2) {
		this.show();
		this.completions_ = this.process_(value);
		if (this.prevLength_ !== value.length) {
			this.activeChoice_ = 0;
		}

		// Add them to dropdown
		if (this.completions_.length == 0) {
			this.addNode_(this.Nodes.EMPTY, false);
		} else {
			for (var i in this.completions_) {
				// TODO add eventthis.list_ener (hover) for this.activeChoice_
				this.addNode_(this.completions_[i], i == this.activeChoice_);
			}
		}

		this.prevLength_ = value.length;
	} else {
		this.hide();
	}
};

Autocompletion.prototype.setPrepareView = function(callback) {
	this.preparationCallback = callback;
};

/**
 * Prepare view to show the result
 */
Autocompletion.prototype.prepareView = function() {
	if (typeof this.preparationCallback === 'undefined') {
		return;
	}
	this.preparationCallback();
};

/**
 * Making a splittable container zone
 */
function ContainerZone(containerNode, rulerNode, titleNode) {
	this.container = document.getElementById(containerNode);
	this.ruler = document.getElementById(rulerNode);
	this.title = document.getElementById(titleNode);
	this.currentLayout = this.Layout.FULL;
	this.widgets = [];
	this.populatedWidgets = [];
	this.initRuler();

	this.focus_ = 0;
	this.focusListeners = [];

	var _this = this;
	this.fallback = function() {
		var emptyWidget = _this.getWidget('New Widget', false);
		emptyWidget.setHTMLContent('<p class="mdl-typography--text-center">Ready !</p>');
		_this.add(emptyWidget);
	};
}

ContainerZone.prototype.Layout = {
	FULL: 'full',
	HORIZONTAL: 'horizontal',
	VERTICAL: 'vertical'
};

/**
 * Define the widget method that would be called when splitting
 */
ContainerZone.prototype.fallbackWidget = function(callback) {
	this.fallback = callback;
};

ContainerZone.prototype.initRuler = function() {
	var context = {};
	var _this = this;

	this.rulerProp = {
		gap: 0.005, // 0.5% margin between two panels
		pos: 0.5
	};

	var initDrag = function(e) {
		context = {
			startX: e.clientX,
			startWidth: parseInt(document.defaultView.getComputedStyle(_this.ruler).width, 10),
			interval: (e.clientX - _this.ruler.offsetLeft)
		};
		document.documentElement.addEventListener('mousemove', doDrag, false);
		document.documentElement.addEventListener('mouseup', stopDrag, false);

		// Prevent selecting text
		e.preventDefault();
	};

	var doDrag = function(e) {
		var relativePosition = (e.clientX - context.interval) / _this.container.offsetWidth;
		_this.rulerProp.pos = relativePosition;
		_this.container.children[0].style.width = (relativePosition - _this.rulerProp.gap) * 100 + '%';
		_this.container.children[1].style.width = ((1 - relativePosition) - _this.rulerProp.gap) * 100 + '%';
		_this.ruler.style.marginLeft = relativePosition * 100 + '%';
	};

	var stopDrag = function() {
		document.documentElement.removeEventListener('mousemove', doDrag, false);
		document.documentElement.removeEventListener('mouseup', stopDrag, false);
	};

	this.ruler.addEventListener('mousedown', initDrag);
};


ContainerZone.prototype.setFocus = function(focus) {
	this.focus_ = focus;
	for (var i = 0 ; i < this.focusListeners.length ; i++) {
		this.focusListeners[i].focusHasChanged(focus);
	}
};

ContainerZone.prototype.getFocus = function() {
	return this.focus_;
};

/**
 * Autobinding implies the widget to be populated as is
 * Will be completed by the user manipulating the widget
 */
ContainerZone.prototype.getWidget = function(name, autobinding) {
	var autobinding = (typeof autobinding === 'undefined'); // Default is true

	for (var i = 0 ; i < this.widgets.length ; i++) {
		if (this.widgets[i].getName() === name) {
			if (autobinding) { // Autobinding
				this.add(this.widgets[i]);
			}
			return this.widgets[i];
		}
	}

	var newWidget = new Widget(name);
	this.widgets.push(newWidget);

	if (autobinding) {
		this.add(newWidget);
	}

	return newWidget;
};

ContainerZone.prototype.getWidgetDOMWrapper = function(widget) {
	var offset = this.populatedWidgets.indexOf(widget);
	if (offset === -1) {
		console.log('Can\'t get DOM wrapper of a non-populated widget');
		return;
	}

	return this.container.children[offset];
};

ContainerZone.prototype.isSplitted = function() {
	return this.currentLayout !== this.Layout.FULL;
};

ContainerZone.prototype.merge = function() {
	if (!this.isSplitted()) {
		return;
	}

	// Reset and clear
	this.ruler.style.marginLeft = '50%';
	this.ruler.style.display = 'none';
	this.rulerProp.pos = 0.5;

	var keep = this.getWidgetDOMWrapper(this.populatedWidgets[this.getFocus()]);
	keep.className = 'rwidget full focus';
	keep.style.width = 'auto';

	for (var i = 0 ; i < this.container.children.length ; i++) {
		if (i != this.getFocus()) {
			this.container.removeChild(this.container.children[i]);
			this.populatedWidgets.splice(i, 1);
		}
	}

	this.setFocus(0)
	this.currentLayout = this.Layout.FULL;
	this.drawTitle();
};

ContainerZone.prototype.split = function(layout) {
	if (this.isSplitted()) {
		return;
	}

	this.ruler.style.display = 'block';
	this.container.children[0].style.width = (this.rulerProp.pos - this.rulerProp.gap) * 100 + '%';

	for (var i = 0 ; i < this.populatedWidgets.length ; i++) {
		this.getWidgetDOMWrapper(this.populatedWidgets[i]).classList.remove('full');
		this.getWidgetDOMWrapper(this.populatedWidgets[i]).classList.add(layout);
	}

	this.currentLayout = layout;

	if (this.populatedWidgets.length <= 1) {
		// We pop the fallback widget
		this.fallback();
	}

	// We want to set the focus on the space
	this.setFocus(1);
	this.drawTitle();
};

ContainerZone.prototype.add = function(widget) {
	if (this.populatedWidgets.indexOf(widget) !== -1) {
		// Can't open the same panel more than once: draw() should be called
		return;
	}

	// Special case at beginning when the widget is already loaded
	if (widget.isAlreadyThere()) {
		this.populatedWidgets.push(widget);
		this.applyFocusEvent_(widget);
		return;
	}

	var widgetElement = document.createElement('div');
	widgetElement.classList.add('rwidget');
	widgetElement.classList.add(this.currentLayout);
	widget.binding(widgetElement);

	if (this.isSplitted()) {
		var layoutFull = this.populatedWidgets.length >= 2;

		// If the container is full, we remove the active widget
		if (layoutFull) {
			// TODO, handle default width 50% -> doesn't consider previous resizing
			this.container.removeChild(this.container.children[this.getFocus()]); // from DOM
			this.populatedWidgets.splice(this.getFocus(), 1);
		}

		if (this.getFocus() === 0 && layoutFull) { // Poping first
			this.populatedWidgets.unshift(widget);
			if (!widget.isAlreadyThere()) {
				this.container.insertBefore(widgetElement, this.container.children[0]);
				this.container.children[0].style.width = (this.rulerProp.pos - this.rulerProp.gap) * 100 + '%';
			}
		} else { // Second panel
			this.populatedWidgets.push(widget);
			if (!widget.isAlreadyThere()) {
				this.container.appendChild(widgetElement);
				this.container.children[1].style.width = ((1 - this.rulerProp.pos) - this.rulerProp.gap) * 100 + '%';
			}
		}
	} else {
		if (this.populatedWidgets.length >= 1) {
			this.container.removeChild(this.container.children[this.getFocus()]); // from DOM
		}
		this.populatedWidgets = [widget];
		if (!widget.isAlreadyThere()) {
			this.container.appendChild(widgetElement);
			this.container.children[0].style.width = 'auto';
		}
	}

	this.moveFocusOnWidget(widget);
	this.applyFocusEvent_(widget);
	widget.setOffset(this.getFocus());
	this.drawTitle();
};

ContainerZone.prototype.moveFocusOnWidget = function(widget) {
	this.setFocus(this.populatedWidgets.indexOf(widget));
	this.container.children[this.getFocus()].classList.add('focus');

	if (this.isSplitted()) {
		this.container.children[(this.getFocus() + 1) % 2 ].classList.remove('focus');
	}

	this.drawTitle();
};

ContainerZone.prototype.drawTitle = function() {
	if (this.layout === this.Layout.FULL || this.populatedWidgets.length === 1) {
		this.title.innerHTML = this.populatedWidgets[0].getName();
	} else {
		var titles = [];
		for (var i = 0 ; i < this.populatedWidgets.length ; i++) {
			if (this.getFocus() == i) {
				titles.push('<strong>' + this.populatedWidgets[i].getName() + '</strong>');
			} else {
				titles.push(this.populatedWidgets[i].getName());
			}
		}
		this.title.innerHTML = titles.join(' & ');
	}
};

ContainerZone.prototype.applyFocusEvent_ = function(widget) {
	var _this = this;
	var element = this.getWidgetDOMWrapper(widget);
	element.addEventListener('mousedown', function() {
		_this.moveFocusOnWidget(widget);
	});
};

ContainerZone.prototype.addFocusListener = function(obj) {
	this.focusListeners.push(obj);
};
'use strict';

(function() {
	var networkerrDialog = document.getElementById('networkerr');
	var isOpen = false;
	var attemps = 0;

	if (!networkerrDialog.showModal) {
		dialogPolyfill.registerDialog(networkerrDialog);
	}

	function retry() {
		attemps++;
		r2.cmdj('?V', function(j) {
			if (typeof j !== 'undefined') {
				attemps = 0;
			}
		});
	}

	networkerrDialog.querySelector('.retry').addEventListener('click', function() {
		networkerrDialog.close();
		retry();
		isOpen = false;
	});

	networkerrDialog.querySelector('.close').addEventListener('click', function() {
		networkerrDialog.close();
		isOpen = false;
	});

	networkerrDialog.querySelector('.ok').addEventListener('click', function() {
		networkerrDialog.close();
		isOpen = false;
	});

	function refresh() {
		if (attemps > 0) {
			var firstAttempt = document.getElementsByClassName('first-attempt');
			for (var i = 0 ; i < firstAttempt.length; i++) {
				firstAttempt[i].style.display = 'none';
			}

			var nextAttempts = document.getElementsByClassName('next-attempt');
			for (var i = 0 ; i < nextAttempts.length; i++) {
				nextAttempts[i].style.display = 'block';
			}
		}
	}

	r2.err = function() {
		if (!isOpen) {
			refresh();
			networkerrDialog.showModal();
		}
	};
})();

var update = function() {/* nop */};
var inColor = true;
var lastView = panelDisasm;

function E(x) {
	return document.getElementById(x);
}

function encode(r) {
	return r.replace(/[\x26\x0A\<>'"]/g, function(r) { return '&#' + r.charCodeAt(0) + ';';});
}

function uiButton(href, label, type) {
	if (type == 'active') {
		return '&nbsp;<a href="' + href.replace(/"/g,'\'') + '" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast" style="background-color:#f04040 !important">' + label + '</a>';
	}
	return '&nbsp;<a href="' + href.replace(/"/g,'\'') + '" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">' + label + '</a>';
}

function clickableOffsets(x) {
	x = x.replace(/0x([a-zA-Z0-9]*)/g,
	'<a href=\'javascript:seek("0x$1")\'>0x$1</a>');
	x = x.replace(/sym\.([\.a-zA-Z0-9_]*)/g,
	'<a href=\'javascript:seek("sym.$1")\'>sym.$1</a>');
	x = x.replace(/fcn\.([\.a-zA-Z0-9_]*)/g,
	'<a href=\'javascript:seek("fcn.$1")\'>fcn.$1</a>');
	x = x.replace(/str\.([\.a-zA-Z0-9_]*)/g,
	'<a href=\'javascript:seek("str.$1")\'>str.$1</a>');
	return x;
}

function write() {
	var str = prompt('hexpairs, quoted string or :assembly');
	if (str != '') {
		switch (str[0]) {
		case ':':
			str = str.substring(1);
			r2.cmd('"wa ' + str + '"', update);
			break;
		case '"':
			str = str.replace(/"/g, '');
			r2.cmd('w ' + str, update);
			break;
		default:
			r2.cmd('wx ' + str, update);
			break;
		}
	}
}

function comment() {
	var addr = prompt('comment');
	if (addr) {
		if (addr == '-') {
			r2.cmd('CC-');
		} else {
			r2.cmd('"CC ' + addr + '"');
		}
		update();
	}
}

function flag() {
	var addr = prompt('flag');
	if (addr) {
		if (addr == '-') {
			r2.cmd('f' + addr);
		} else {
			r2.cmd('f ' + addr);
		}
		update();
	}
}

function block() {
	var size = prompt('block');
	if (size && size.trim()) {
		r2.cmd('b ' + size);
		update();
	}
}

function flagsize() {
	var size = prompt('size');
	if (size && size.trim()) {
		r2.cmd('fl $$ ' + size);
		update();
	}
}

function seek(x) {
	if (x === undefined) {
		var addr = prompt('address');
	} else {
		var addr = x;
	}
	if (addr && addr.trim() != '') {
		r2.cmd('s ' + addr);
		lastView();
		document.getElementById('content').scrollTop = 0;
		update();
	}
}

function analyze() {
	r2.cmd('af', function() {
		panelDisasm();
	});
}
function uiCheckList(grp, id, label) {
	return '<li> <label for="' + grp + '" class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect"> <input type="checkbox" id="' + id + '" class="mdl-checkbox__input" /><span class="mdl-checkbox__label">' + label + '</span> </label> </li>';
}

function notes() {
	var widget = widgetContainer.getWidget('Notes');
	var dom = widgetContainer.getWidgetDOMWrapper(widget);

	var out = '<br />' + uiButton('javascript:panelComments()', '&lt; Comments');
	out += '<br /><br /><textarea rows=32 style="width:100%"></textarea>';
	c.innerHTML = out;
}

function setFlagspace(fs) {
	if (!fs) fs = prompt('name');
	if (!fs) return;
	r2.cmd('fs ' + fs, function() {
		flagspaces();
	});
}

function renameFlagspace(fs) {
	if (!fs) fs = prompt('name');
	if (!fs) return;
	r2.cmd('fsr ' + fs, function() {
		flagspaces();
	});
}

function delFlagspace(fs) {
	if (!fs) fs = '.';
	if (!fs) return;
	r2.cmd('fs-' + fs, function() {
		flagspaces();
	});
}

function delAllFlags() {
	r2.cmd('f-*', function() {
		panelFlags();
	});
}

function setNullFlagspace(fs) {
	updates.registerMethod(widgetContainer.getFocus(), fs ? panelFlags : flagspaces);
	r2.cmd('fs *', function() {
		flagspaces();
	});
}

/* rename to panelFlagSpaces */
function flagspaces() {

	var widget = widgetContainer.getWidget('Flag Spaces');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	updates.registerMethod(widget.getOffset(), flagspaces);

	c.innerHTML = '<br />&nbsp;' + uiRoundButton('javascript:panelFlags()', 'undo');
	c.innerHTML += '&nbsp;' + uiButton('javascript:setNullFlagspace()', 'Deselect');
	c.innerHTML += '&nbsp;' + uiButton('javascript:setFlagspace()', 'Add');
	c.innerHTML += '&nbsp;' + uiButton('javascript:delFlagspace()', 'Delete');
	c.innerHTML += '&nbsp;' + uiButton('javascript:renameFlagspace()', 'Rename');
	c.innerHTML += '<br /><br />';
	r2.cmd('fs', function(d) {
		var lines = d.split(/\n/);
		var body = uiTableBegin(['+Flags', 'Flagspace']);
		for (var i in lines) {
			var line = lines[i].split(/ +/);
			if (line.length >= 4) {
				var selected = line[2].indexOf('.') == -1;
				var a = '';
				a += '<a href="javascript:setFlagspace(\'' + line[3] + '\')">';
				if (selected) a += '<font color=\'red\'>' + line[3] + '</font>';
				else a += line[3];
				a += '</a>';
				body += uiTableRow([
				'+' + line[1], a
				]);
			}
		}
		body += uiTableEnd();
		c.innerHTML += body;
	});
}

function analyzeSymbols() {
	statusMessage('Analyzing symbols...');
	r2.cmd('aa',function() {
		statusMessage('done');
		update();
	});
}
function analyzeRefs() {
	statusMessage('Analyzing references...');
	r2.cmd('aar',function() {
		statusMessage('done');
		update();
	});
}
function analyzeCalls() {
	statusMessage('Analyzing calls...');
	r2.cmd('aac',function() {
		statusMessage('done');
		update();
	});
}
function analyzeFunction() {
	statusMessage('Analyzing function...');
	r2.cmd('af',function() {
		statusMessage('done');
		update();
	});
}
function analyzeNames() {
	statusMessage('Analyzing names...');
	r2.cmd('.afna @@ fcn.*',function() {
		statusMessage('done');
		update();
	});
}

function smallDisasm() {
	r2.cmd('e asm.bytes=false');
	r2.cmd('e asm.lines=false');
	r2.cmd('e asm.cmtright=false');
}

function mediumDisasm() {
	r2.cmd('e asm.bytes=false');
	r2.cmd('e asm.lines=true');
	r2.cmd('e asm.lineswidth=8');
	r2.cmd('e asm.cmtright=false');
}

function largeDisasm() {
	r2.cmd('e asm.bytes=true');
	r2.cmd('e asm.lines=true');
	r2.cmd('e asm.lineswidth=12');
	r2.cmd('e asm.cmtright=true');
}

function configPseudo() {
	r2.cmd('e asm.pseudo=1');
	r2.cmd('e asm.syntax=intel');
}

function configOpcodes() {
	r2.cmd('e asm.pseudo=0');
	r2.cmd('e asm.syntax=intel');
}

function configATT() {
	r2.cmd('e asm.pseudo=0');
	r2.cmd('e asm.syntax=att');
}

function panelAbout() {
	r2.cmd('?V', function(version) {
		alert('radare2 material webui by --pancake @ 2015-2016\n\n'+version.trim());
	});
}

function configColorDefault() {
	r2.cmd('ecd', function() {
		update();
	});
}
function configColorRandom() {
	r2.cmd('ecr', function() {
		update();
	});
}

function configColorTheme(theme) {
	r2.cmd('eco ' + theme, function() {
		update();
	});
}

function configPA() {
	r2.cmd('e io.va=false');
}

function configVA() {
	r2.cmd('e io.va=true');
}

function configDebug() {
	r2.cmd('e io.va=true');
	r2.cmd('e io.debug=true');
}

function configArch(name) { r2.cmd('e asm.arch=' + name); }
function configBits8() { r2.cmd('e asm.bits=8'); }
function configBits16() { r2.cmd('e asm.bits=16'); }
function configBits32() { r2.cmd('e asm.bits=32'); }
function configBits64() { r2.cmd('e asm.bits=64'); }
function configColorTrue() { inColor = true; }
function configColorFalse() { inColor = false; }

var comboId = 0;

function uiCombo(d) {
	var fun_name = 'combo' + (++comboId);
	var fun = fun_name + ' = function(e) {';
	fun += ' var sel = document.getElementById("opt_' + fun_name + '");';
	fun += ' var opt = sel.options[sel.selectedIndex].value;';
	fun += ' switch (opt) {';
	for (var a in d) {
		fun += 'case "' + d[a].name + '": ' + d[a].js + '(' + d[a].name + ');break;';
	}
	fun += '}}';
	// CSP violation here
	eval(fun);
	var out = '<select id="opt_' + fun_name + '" onchange="' + fun_name + '()">';
	for (var a in d) {
		var def = (d[a].default) ? ' default' : '';
		out += '<option' + def + '>' + d[a].name + '</option>';
	}
	out += '</select>';
	return out;
}

function uiSwitch(d) {
	// TODO: not yet done
	var out = '' + d +
	'<label class="mdl-switch mdl-js-switch mdl-js-ripple-effect" for="switch-1">' +
	'<input type="checkbox" id="switch-1" class="mdl-switch__input" checked />' +
	'<span class="mdl-switch__label"></span>' +
	'</label>';
	return out;
}

function uiBlock(d) {
	var out = '<div class="mdl-card__supporting-text mdl-shadow--2dp mdl-color-text--blue-grey-50 mdl-cell" style="display:inline-block;margin:5px;color:black !important;background-color:white !important">';
	out += '<h3 style="color:black">' + d.name + '</h3>';
	for (var i in d.blocks) {
		var D = d.blocks[i];
		out += '<br />' + D.name + ': ';
		out += uiCombo(D.buttons);
	}
	out += '</div>';
	return out;
}

function panelSettings() {
	var out = '';

	var widget = widgetContainer.getWidget('Settings');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	updates.registerMethod(widget.getOffset(), panelSettings);

	c.style.backgroundColor = '#f0f0f0';
	out += '<div style=\'margin:10px\'>';
	out += uiBlock({ name: 'Platform', blocks: [
	{ name: 'Arch', buttons: [
	{ name: 'x86', js: 'configArch', default: true },
	{ name: 'arm', js: 'configArch' },
	{ name: 'mips', js: 'configArch' },
	{ name: 'java', js: 'configArch' },
	{ name: 'dalvik', js: 'configArch' },
	{ name: '6502', js: 'configArch' },
	{ name: '8051', js: 'configArch' },
	{ name: 'h8300', js: 'configArch' },
	{ name: 'hppa', js: 'configArch' },
	{ name: 'i4004', js: 'configArch' },
	{ name: 'i8008', js: 'configArch' },
	{ name: 'lh5801', js: 'configArch' },
	{ name: 'lm32', js: 'configArch' },
	{ name: 'm68k', js: 'configArch' },
	{ name: 'malbolge', js: 'configArch' },
	{ name: 'mcs96', js: 'configArch' },
	{ name: 'msp430', js: 'configArch' },
	{ name: 'nios2', js: 'configArch' },
	{ name: 'ppc', js: 'configArch' },
	{ name: 'rar', js: 'configArch' },
	{ name: 'sh', js: 'configArch' },
	{ name: 'snes', js: 'configArch' },
	{ name: 'sparc', js: 'configArch' },
	{ name: 'spc700', js: 'configArch' },
	{ name: 'sysz', js: 'configArch' },
	{ name: 'tms320', js: 'configArch' },
	{ name: 'v810', js: 'configArch' },
	{ name: 'v850', js: 'configArch' },
	{ name: 'ws', js: 'configArch' },
	{ name: 'xcore', js: 'configArch' },
	{ name: 'prospeller', js: 'configArch' },
	{ name: 'gb', js: 'configArch' },
	{ name: 'z80', js: 'configArch' },
	{ name: 'arc', js: 'configArch' },
	{ name: 'avr', js: 'configArch' },
	{ name: 'bf', js: 'configArch' },
	{ name: 'cr16', js: 'configArch' },
	{ name: 'cris', js: 'configArch' },
	{ name: 'xap', js: 'configArch' },
	{ name: 'dcpu16', js: 'configArch' },
	{ name: 'ebc', js: 'configArch' }
	]},
	{ name: 'Bits', buttons: [
	{ name: '64', js: 'configBits64' },
	{ name: '32', js: 'configBits32', default: true },
	{ name: '16', js: 'configBits16' },
	{ name: '8', js: 'configBits8' }
	]},
	{ name: 'OS', buttons: [
	{ name: 'Linux', js: 'configOS_LIN', default: true },
	{ name: 'Windows', js: 'configOS_W32' },
	{ name: 'OSX', js: 'configOS_OSX' }
	]}
	]
	});
	out += uiBlock({ name: 'Disassembly', blocks: [
	{
	name: 'Size', buttons: [
	{ name: 'S', js: 'smallDisasm' },
	{ name: 'M', js: 'mediumDisasm' },
	{ name: 'L', js: 'largeDisasm' }
	]},
	{
	name: 'Decoding', buttons: [
	{ name: 'Pseudo', js: 'configPseudo' },
	{ name: 'Opcodes', js: 'configOpcodes' },
	{ name: 'ATT', js: 'configATT' }
	]},
		       {
			name: 'Colors', buttons: [
			{ name: 'Yes', js: 'configColorTrue', default: true },
			{ name: 'No', js: 'configColorFalse' }
			]
		}, {
			name: 'Theme', buttons: [
				{ name: 'Default', js: 'configColorDefault' },
				{ name: 'Random', js: 'configColorRandom' },
				{ name: 'Solarized', js: 'configColorTheme("solarized")' },
				{ name: 'Ogray', js: 'configColorTheme("ogray")' },
				{ name: 'Twilight', js: 'configColorTheme("twilight")' },
				{ name: 'Rasta', js: 'configColorTheme("rasta")' },
				{ name: 'Tango', js: 'configColorTheme("tango")' },
				{ name: 'White', js: 'configColorTheme("white")' }
				]}
						]
		});
	out += uiBlock({ name: 'Core/IO', blocks: [
		{
			name: 'Mode', buttons: [
			{ name: 'PA', js: 'configPA' },
			{ name: 'VA', js: 'configVA' },
			{ name: 'Debug', js: 'configDebug' }
			]
		}
]});
	out += uiBlock({ name: 'Analysis', blocks: [
		{
			name: 'HasNext', buttons: [
			{ name: 'Yes', js: 'configAnalHasnextTrue', default: true },
			{ name: 'No', js: 'configAnalHasnextFalse' }
			]
		},{
			name: 'Skip Nops', buttons: [
			{ name: 'Yes', js: 'configAnalNopskipTrue', default: true },
			{ name: 'No', js: 'configAnalNopskipFalse' }
			]
		},{
			name: 'NonCode', buttons: [
			{ name: 'Yes', js: 'configAnalNoncodeTrue' },
			{ name: 'No', js: 'configAnalNoncodeFalse', default: true }
			]
		}
		]});
	out += '</div>';
	c.innerHTML = out;
}

function printHeaderPanel(title, cmd, grep) {
	var widget = widgetContainer.getWidget(title);
	widget.setDark();
	var dom = widgetContainer.getWidgetDOMWrapper(widget);

	// TODO, warning? panelFunction // printHeaderPanel (not a complete widget)
	updates.registerMethod(widget.getOffset(), panelFunctions);

	var c = document.createElement('div');
	dom.innerHTML = '';
	dom.appendChild(c);

	c.style.color = '#202020 !important';
	c.style.backgroundColor = '#202020';
	var out = '' ; //
	/*
	out += ''
	+' <div class="mdl-tabs mdl-js-tabs">'
	+'  <div class="mdl-tabs__tab-bar mds-js-ripple-effect">'
	+'    <a href="#tab1-panel" class="mdl-tabs__tab is-active">Headers</a>'
	+'    <a href="#tab2-panel" class="mdl-tabs__tab">Symbols</a>'
	+'    <a href="#tab3-panel" class="mdl-tabs__tab">Imports</a>'
	+'    <a href="#tab4-panel" class="mdl-tabs__tab">Relocs</a>'
	+'    <a href="#tab5-panel" class="mdl-tabs__tab">Sections</a>'
	+'    <a href="#tab6-panel" class="mdl-tabs__tab">SDB</a>'
	+'  </div>'
	+'  <div class="mdl-tabs__panel is-active" id="tab1-panel">'
	+'    <p>Tab 1 Content</p>'
	+'  </div>'
	+'  <div class="mdl-tabs__panel" id="tab2-panel">'
	+'    <p>Tab 2 Content</p>'
	+'  </div>'
	+'  <div class="mdl-tabs__panel" id="tab3-panel">'
	+'    <p>Tab 3 Content</p>'
	+'  </div>'
	+'</div>';
*/
	out += '<div style=\'position:fixed;margin:0.5em\'>';
	out += '&nbsp;' + uiRoundButton('javascript:location.href="/m"', 'undo');
	out += uiButton('javascript:panelHeaders()', 'Headers');
	out += uiButton('javascript:panelSymbols()', 'Symbols');
	out += uiButton('javascript:panelImports()', 'Imports');
	out += uiButton('javascript:panelRelocs()', 'Relocs');
	out += uiButton('javascript:panelSections()', 'Sections');
	out += uiButton('javascript:panelStrings()', 'Strings');
	out += uiButton('javascript:panelSdb()', 'Sdb');
	out += '</div><br /><br /><br /><br />';
	c.innerHTML = out;

	if (grep) {
		cmd += '~' + grep;
	}
	r2.cmd(cmd, function(d) {
		var color = '#f0f0f0';
		d = clickableOffsets(d);
		c.innerHTML += '<pre style=\'margin:1.2em;color:' + color + ' !important\'>' + d + '<pre>';
	});
}

function panelSdb() {
	printHeaderPanel('SDB', 'k bin/cur/***');
}
function panelSections() {
	printHeaderPanel('Sections', 'iSq');
}
function panelStrings() {
	printHeaderPanel('Strings', 'izq');
}
function panelImports() {
	printHeaderPanel('Imports', 'isq', ' imp.');
}

function panelRelocs() {
	printHeaderPanel('Relocs', 'ir');
}

function panelSymbols() {
	printHeaderPanel('Imports', 'isq', '!imp');
}

function panelHeaders() {
	printHeaderPanel('Headers', 'ie;i');
}

function panelFunctions() {
	var widget = widgetContainer.getWidget('Functions');
	widget.setDark();
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	updates.registerMethod(widget.getOffset(), panelFunctions);

	c.style.backgroundColor = '#f0f0f0';
	var body = '<br />';
	body += uiButton('javascript:analyzeSymbols()', 'Symbols');
	body += uiButton('javascript:analyzeCalls()', 'Calls');
	body += uiButton('javascript:analyzeFunction()', 'Function');
	body += uiButton('javascript:analyzeRefs()', 'Refs');
	body += uiButton('javascript:analyzeNames()', 'AutoName');
	body += '<br /><br />';
	c.innerHTML = body;
	r2.cmd('e scr.utf8=false');
	r2.cmd('afl', function(d) {
		//var dis = clickableOffsets (d);
		//c.innerHTML += "<pre style='font-family:Console,Courier New,monospace' style='color:white !important'>"+dis+"<pre>";

		var table = new Table(
			['+Address', 'Name', '+Size', '+CC'],
			[false, true, false, false],
			'functionTable');

		var lines = d.split(/\n/); //clickableOffsets (d).split (/\n/);
		for (var i in lines) {
			var line = lines[i].split(/ +/);
			if (line.length >= 3) {
				table.addRow([line[0], line[3], line[1], line[2]]);
			}
		}
		table.insertInto(c);
	});

}

var last_console_output = '';

function runCommand(text) {
	if (!text)
	text = document.getElementById('input').value;
	r2.cmd(text, function(d) {
		last_console_output = '\n' + d;
		document.getElementById('output').innerHTML = last_console_output;
	});
}

function consoleKey(e) {
	var inp = document.getElementById('input');
	if (!e) {
		inp.onkeypress = consoleKey;
	} else {
		if (e.keyCode == 13) {
			runCommand(inp.value);
			inp.value = '';
		}
	}
}

function singlePanel() {
	window.top.location.href = '/m/';
}
function hSplit() {
	location.href = '/m/hsplit';
}
function vSplit() {
	location.href = '/m/vsplit';
}

function panelConsole() {
	var widget = widgetContainer.getWidget('Console');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	updates.registerMethod(widget.getOffset(), panelConsole);

	c.innerHTML = '<br />';
	if (inColor) {
		c.style.backgroundColor = '#202020';
		c.innerHTML += '<input style=\'position:fixed;padding-left:10px;top:4em;height:1.8em;color:white\' onkeypress=\'consoleKey()\' class=\'mdl-card--expand mdl-textfield__input\' id=\'input\'/>';
		//c.innerHTML += uiButton('javascript:runCommand()', 'Run');
		c.innerHTML += '<div id=\'output\' class=\'pre\' style=\'color:white !important\'><div>';
	} else {
		c.style.backgroundColor = '#f0f0f0';
		c.innerHTML += '<input style=\'color:black\' onkeypress=\'consoleKey()\' class=\'mdl-card--expand mdl-textfield__input\' id=\'input\'/>';
		c.innerHTML += uiButton('javascript:runCommand()', 'Run');
		c.innerHTML += '<div id=\'output\' class=\'pre\' style=\'color:black!important\'><div>';
	}
	document.getElementById('output').innerHTML = last_console_output;
}

function searchKey(e) {
	var inp = document.getElementById('search_input');
	if (!e) {
		inp.onkeypress = searchKey;
	} else {
		if (e.keyCode == 13) {
			runSearch(inp.value);
			inp.value = '';
		}
	}
}
function runSearchMagic() {
	r2.cmd('/m', function(d) {
		document.getElementById('search_output').innerHTML = clickableOffsets(d);
	});
}
function runSearchCode(text) {
	if (!text) text = document.getElementById('search_input').value;
	r2.cmd('"/c ' + text + '"', function(d) {
		document.getElementById('search_output').innerHTML = clickableOffsets(d);
	});
}
function runSearchString(text) {
	if (!text) text = document.getElementById('search_input').value;
	r2.cmd('/ ' + text, function(d) {
		document.getElementById('search_output').innerHTML = clickableOffsets(d);
	});
}
function runSearchROP(text) {
	if (!text) text = document.getElementById('search_input').value;
	r2.cmd('"/R ' + text + '"', function(d) {
		document.getElementById('search_output').innerHTML = clickableOffsets(d);
	});
}

function runSearch(text) {
	if (!text)
	text = document.getElementById('search_input').value;
	if (text[0] == '"') {
		r2.cmd('"/ ' + text + '"', function(d) {
			document.getElementById('search_output').innerHTML = clickableOffsets(d);
		});
	} else {
		r2.cmd('"/x ' + text + '"', function(d) {
			document.getElementById('search_output').innerHTML = clickableOffsets(d);
		});
	}
}

function indentScript() {
	var str = document.getElementById('script').value;
	var indented = js_beautify(str);
	document.getElementById('script').value = indented;
	localStorage['script'] = indented;
}

function runScript() {
	var str = document.getElementById('script').value;
	localStorage['script'] = str;
	document.getElementById('scriptOutput').innerHTML = '';
	try {
		var msg = '"use strict";' +
		'function log(x) { var a = ' +
		'document.getElementById(\'scriptOutput\'); ' +
		'if (a) a.innerHTML += x + \'\\n\'; }\n';
		// CSP violation here
		eval(msg + str);
	} catch (e) {
		alert(e);
	}
}

var foo = '';
function toggleScriptOutput() {
	var o = document.getElementById('scriptOutput');
	if (o) {
		if (foo == '') {
			foo = o.innerHTML;
			o.innerHTML = '';
		} else {
			o.innerHTML = foo;
			foo = '';
		}
	}
}

function panelScript() {
	var widget = widgetContainer.getWidget('Script');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	updates.registerMethod(widget.getOffset(), panelScript);

	c.style.backgroundColor = '#f0f0f0';
	var localScript = localStorage.getItem('script');
	var out = '<br />' + uiButton('javascript:runScript()', 'Run');
	out += '&nbsp;' + uiButton('javascript:indentScript()', 'Indent');
	out += '&nbsp;' + uiButton('javascript:toggleScriptOutput()', 'Output');
	out += '<br /><div class="output" id="scriptOutput"></div><br />';
	out += '<textarea rows=32 id="script" class="pre" style="width:100%">';
	if (!localScript) {
		localScript = 'r2.cmd("?V", log);';
	}
	out += localScript + '</textarea>';
	c.innerHTML = out;
}

function panelSearch() {
	var widget = widgetContainer.getWidget('Search');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	updates.registerMethod(widget.getOffset(), panelSearch);

	c.style.backgroundColor = '#f0f0f0';
	var out = '<br />';
	out += '<input style=\'background-color:white !important;padding-left:10px;top:3.5em;height:1.8em;color:white\' onkeypress=\'searchKey()\' class=\'mdl-card--expand mdl-textfield__input\' id=\'search_input\'/>';
	out += '<br />';
	out += uiButton('javascript:runSearch()', 'Hex');
	out += uiButton('javascript:runSearchString()', 'String');
	out += uiButton('javascript:runSearchCode()', 'Code');
	out += uiButton('javascript:runSearchROP()', 'ROP');
	out += uiButton('javascript:runSearchMagic()', 'Magic');
	out += '<br /><br />';
	out += '<div id=\'search_output\' class=\'pre\' style=\'color:black!important\'><div>';
	c.innerHTML = out;
}

function panelFlags() {
	var widget = widgetContainer.getWidget('Flags');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	updates.registerMethod(widget.getOffset(), panelFlags);

	c.style.backgroundColor = '#f0f0f0';
	c.innerHTML = '<br />';
	c.innerHTML += uiButton('javascript:flagspaces()', 'Spaces');
	c.innerHTML += uiButton('javascript:delAllFlags()', 'DeleteAll');
	c.innerHTML += '<br /><br />';
	r2.cmd('f', function(d) {
		var lines = d.split(/\n/); //clickableOffsets (d).split (/\n/);
		var body = uiTableBegin(['+Offset', '+Size', 'Name']);
		for (var i in lines) {
			var line = lines[i].split(/ /);
			if (line.length >= 3)
			body += uiTableRow([
			'+' + line[0],
			'+' + line[1],
			line[2]
			]);
		}
		body += uiTableEnd();
		c.innerHTML += body;
	});
}

function panelComments() {
	var widget = widgetContainer.getWidget('Comments');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	updates.registerMethod(widget.getOffset(), panelComments);

	c.style.backgroundColor = '#f0f0f0';
	c.innerHTML = '<br />';
	c.innerHTML += uiButton('javascript:notes()', 'Notes');
	c.innerHTML += '<br /><br />';
	r2.cmd('CC', function(d) {
		var lines = d.split(/\n/); //clickableOffsets (d).split (/\n/);
		var body = uiTableBegin(['+Offset', 'Comment']);
		for (var i in lines) {
			var line = lines[i].split(/ (.+)?/);
			if (line.length >= 2)
			body += uiTableRow([
			'+' + line[0],
			'+' + line[1]
			]);
		}
		body += uiTableEnd();
		c.innerHTML += body;
	});
}

function up() {
	r2.cmd('s--');
	update();
}

function down() {
	r2.cmd('s++');
	update();
}

function panelHexdump() {
	var widget = widgetContainer.getWidget('Hexdump');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	updates.registerMethod(widget.getOffset(), panelHexdump);
	lastViews.registerMethod(widget.getOffset(), panelHexdump);

	if (inColor) {
		c.style.backgroundColor = '#202020';
	}
	var out = '<div style=\'position:fixed;margin:0.5em\'>';
	out += uiButton('javascript:comment()', 'Comment');
	out += uiButton('javascript:write()', 'Write');
	out += uiButton('javascript:flag()', 'Flag');
	out += uiButton('javascript:flagsize()', 'Size');
	out += uiButton('javascript:block()', 'Block');
	out += '</div><br /><br /><br />';
	c.innerHTML = out;
	var tail = inColor ? '@e:scr.color=1,scr.html=1' : '';
	r2.cmd('pxa 4096' + tail, function(d) {
		var color = inColor ? 'white' : 'black';
		d = clickableOffsets(d);
		var pre = '<div><center>' + uiRoundButton('javascript:up()', 'keyboard_arrow_up');
		pre += uiRoundButton('javascript:down()', 'keyboard_arrow_down') + '</center></div>';
		var pos = '<div><center>' + uiRoundButton('javascript:down()', 'keyboard_arrow_down') + '</center></div>';
		c.innerHTML += pre + '<pre style=\'color:' + color + '!important\'>' + d + '<pre>' + pos;
	});
}

function uiRoundButton(a, b, c) {
	var out = '';
	out += '<button onclick=' + a + ' class="mdl-button mdl-js-button mdl-button--fab mdl-js-ripple-effect" ' + c + '>';
	out += '<i class="material-icons" style="opacity:1">' + b + '</i>';
	out += '</button>';
	return out;
}

function panelDisasm() {
	var widget = widgetContainer.getWidget('Disassembly');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	updates.registerMethod(widget.getOffset(), panelDisasm);
	lastViews.registerMethod(widget.getOffset(), panelDisasm);

	if (inColor) {
		c.style.backgroundColor = '#202020';
	}
	var out = '<div style=\'position:fixed;margin:0.5em\'>';
	out += uiRoundButton('javascript:up()', 'keyboard_arrow_up');
	out += uiRoundButton('javascript:down()', 'keyboard_arrow_down');
	out += '&nbsp;';
	out += uiButton('javascript:analyze()', 'ANLZ');
	out += uiButton('javascript:comment()', 'CMNT');
	out += uiButton('javascript:info()', 'Info');
	out += uiButton('javascript:rename()', 'RNME');
	out += uiButton('javascript:write()', 'Wrte');
	out += '</div><br /><br /><br />';

	c.innerHTML = out;
	c.style['font-size'] = '12px';
	var tail = '';
	if (inColor) {
		tail = '@e:scr.color=1,scr.html=1';
	}

	r2.cmd('pd 128' + tail, function(d) {
		var dis = clickableOffsets(d);
		ret = '';
		ret += '<center>' + uiRoundButton('javascript:up()', 'keyboard_arrow_up') + uiRoundButton('javascript:down()', 'keyboard_arrow_down') + '</center>';
		ret += '<pre style=\'color:grey\'>' + dis + '<pre>';
		ret += '<center>' + uiRoundButton('javascript:down()', 'keyboard_arrow_down') + '</center><br /><br />';

		c.innerHTML += ret;
	});
}

var nativeDebugger = false;

function srpc() {
	r2.cmd('sr pc', update);
}
function stepi() {
	if (nativeDebugger) {
		r2.cmd('ds', update);
	} else {
		r2.cmd('aes', update);
	}
}
function cont() {
	if (nativeDebugger) {
		r2.cmd('dc', update);
	} else {
		r2.cmd('aec', update);
	}
}
function setbp() {
	r2.cmd('db $$', update);
}
function setreg() {
	var expr = prompt('register=value');
	if (expr != '') {
		if (nativeDebugger) {
			r2.cmd('dr ' + expr + ';.dr*', update);
		} else {
			r2.cmd('aer ' + expr + ';.ar*', update);
		}
	}
}

function panelDebug() {
	r2.cmd('e cfg.debug', function(x) {
		nativeDebugger = (x.trim() == 'true');
	});

	var widget = widgetContainer.getWidget('Debugger');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	updates.registerMethod(widget.getOffset(), panelDebug);
	lastViews.registerMethod(widget.getOffset(), panelDebug);

	if (inColor) {
		c.style.backgroundColor = '#202020';
	}
	var out = '<div style=\'position:fixed;margin:0.5em\'>';
	out += uiRoundButton('javascript:up()', 'keyboard_arrow_up');
	out += uiRoundButton('javascript:down()', 'keyboard_arrow_down');
	out += '&nbsp;';
	out += uiButton('javascript:srpc()', 'PC');
	out += uiButton('javascript:stepi()', 'Step');
	out += uiButton('javascript:cont()', 'Cont');
	out += uiButton('javascript:setbp()', 'BP');
	out += uiButton('javascript:setreg()', 'REG');
	out += '</div><br /><br /><br /><br />';
	c.innerHTML = out;
	var tail = '';
	if (inColor) {
		tail = '@e:scr.color=1,scr.html=1';
	}
	// stack
	if (nativeDebugger) {
		var rcmd = 'dr';
	} else {
		var rcmd = 'ar';
	}
	r2.cmd('f cur;.' + rcmd + '*;sr sp;px 64', function(d) {
		var dis = clickableOffsets(d);
		c.innerHTML += '<pre style=\'margin:10px;color:grey\'>' + dis + '<pre>';
	});
	r2.cmd(rcmd + '=;s cur;f-cur;pd 128' + tail, function(d) {
		var dis = clickableOffsets(d);
		c.innerHTML += '<pre style=\'color:grey\'>' + dis + '<pre>';
	});
}

function saveProject() {
	r2.cmd('Ps', function() {
		alert('Project saved');
	});
}
function deleteProject() {
	alert('Project deleted');
	location.href = 'open.html';
}
function closeProject() {
	alert('Project closed');
	location.href = 'open.html';
}
function rename() {
	var name = prompt('name');
	if (name && name.trim() != '') {
		r2.cmd('afn ' + name);
		r2.cmd('f ' + name);
		update();
	}
}
function info() {
	var widget = widgetContainer.getWidget('Info');
	widget.setDark();
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	var color = inColor ? 'white' : 'black';
	var out = '<br />'; //Version: "+d;
	out += uiRoundButton('javascript:panelDisasm()', 'undo');
	out += '&nbsp;';
	out += uiButton('javascript:pdtext()', 'Full');
	out += uiButton('javascript:pdf()', 'Func');
	out += uiButton('javascript:graph()', 'Graph');
	out += uiButton('javascript:blocks()', 'Blocks');
	out += uiButton('javascript:decompile()', 'Decompile');
	c.innerHTML = out;
	r2.cmd('afi', function(d) {
		c.innerHTML += '<pre style=\'color:' + color + '\'>' + d + '<pre>';
	});
}

function blocks() {
	var widget = widgetContainer.getWidget('Blocks');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	c.style['overflow'] = 'none';
	var color = inColor ? 'white' : 'black';
	c.innerHTML = '<br />';
	c.innerHTML += '&nbsp;<a href="javascript:panelDisasm()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">&lt; INFO</a> <h3 color=white></h3>';
	var tail = inColor ? '@e:scr.color=1,scr.html=1' : '';
	r2.cmd('pdr' + tail, function(d) {
		c.innerHTML += '<pre style=\'color:' + color + '\'>' + d + '<pre>';
	});
}

function pdtext() {
	var widget = widgetContainer.getWidget('Function');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	c.style['overflow'] = 'none';
	var color = inColor ? 'white' : 'black';
	c.innerHTML = '<br />';
	c.innerHTML += '&nbsp;<a href="javascript:panelDisasm()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">&lt; INFO</a> <h3 color=white></h3>';
	var tail = inColor ? '@e:scr.color=1,scr.html=1,asm.lineswidth=0' : '@e:asm.lineswidth=0';
	r2.cmd('e scr.color=1;s entry0;s $S;pD $SS;e scr.color=0', function(d) {
		d = clickableOffsets(d);
		c.innerHTML += '<pre style=\'color:' + color + '\'>' + d + '<pre>';
	});
}

function pdf() {
	var widget = widgetContainer.getWidget('Function');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	c.style['overflow'] = 'none';
	var color = inColor ? 'white' : 'black';
	c.innerHTML = '<br />';
	c.innerHTML += '&nbsp;<a href="javascript:panelDisasm()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">&lt; INFO</a> <h3 color=white></h3>';
	var tail = inColor ? '@e:scr.color=1,scr.html=1,asm.lineswidth=0' : '@e:asm.lineswidth=0';
	r2.cmd('pdf' + tail, function(d) {
		c.innerHTML += '<pre style=\'color:' + color + '\'>' + d + '<pre>';
	});
}

function decompile() {
	var widget = widgetContainer.getWidget('Decompile');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	c.style['overflow'] = 'none';
	var color = inColor ? 'white' : 'black';
	c.innerHTML = '<br />';
	c.innerHTML += '&nbsp;<a href="javascript:panelDisasm()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">&lt; INFO</a> <h3 color=white></h3>';
	var tail = inColor ? '@e:scr.color=1,scr.html=1' : '';
	r2.cmd('pdc' + tail, function(d) {
		c.innerHTML += '<pre style=\'color:' + color + '\'>' + d + '<pre>';
	});
}

function graph() {
	var widget = widgetContainer.getWidget('Graph');
	widget.setDark();
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	c.style['overflow'] = 'auto';
	var color = inColor ? 'white' : 'black';
	c.innerHTML = '<br />&nbsp;<a href="javascript:panelDisasm()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">&lt; INFO</a>';
	var tail = inColor ? '@e:scr.color=1,scr.html=1' : '';
	r2.cmd('agf' + tail, function(d) {
		d = clickableOffsets(d);
		c.innerHTML += '<pre style=\'color:' + color + '\'>' + d + '<pre>';
	});
}

//-------------

Array.prototype.forEach.call(document.querySelectorAll('.mdl-card__media'), function(el) {
	var link = el.querySelector('a');
	if (!link) {
		return;
	}
	var target = link.getAttribute('href');
	if (!target) {
		return;
	}
	el.addEventListener('click', function() {
		location.href = target;
	});
});

function updateFortune() {
	r2.cmd('fo', function(d) {
		document.getElementById('fortune').innerHTML = d;
		readFortune();
	});
}

// say a message
function speak(text, callback) {
    var u = new SpeechSynthesisUtterance();
    u.text = text;
    u.lang = 'en-US';
 
    u.onend = function () {
        if (callback) {
            callback();
        }
    };
 
    u.onerror = function (e) {
        if (callback) {
            callback(e);
        }
    };
 
    speechSynthesis.speak(u);
}

function readFortune() {
	var f = document.getElementById('fortune').innerHTML;
	speak (f);
}

function updateInfo() {
	r2.cmd('i', function(d) {
		var lines = d.split(/\n/g);
		var lines1 = lines.slice(0,lines.length / 2);
		var lines2 = lines.slice(lines.length / 2);
		var body = '';

		body += '<table style=\'width:100%\'><tr><td>';
		for (var i in lines1) {
			var line = lines1[i].split(/ (.+)?/);
			if (line.length >= 2)
			body += '<b>' + line[0] + '</b> ' + line[1] + '<br/>';
		}
		body += '</td><td>';
		for (var i in lines2) {
			var line = lines2[i].split(/ (.+)?/);
			if (line.length >= 2)
			body += '<b>' + line[0] + '</b> ' + line[1] + '<br/>';
		}
		body += '</td></tr></table>';
		document.getElementById('info').innerHTML = body;
	});
}

function updateEntropy() {
	var eg = document.getElementById('entropy-graph');
	var box = eg.getBoundingClientRect();
	var height = (0 | box.height) - 35 - 19;
	r2.cmd('p=ej 50 $s @ $M', function(d) {
		var body = '';
		var res = JSON.parse(d);
		var values = new Array();

		for (var i in res['entropy']) values.push(res['entropy'][i]['value']);

		var nbvals = values.length;
		var min = Math.min.apply(null, values);
		var max = Math.max.apply(null, values);
		var inc = 500.0 / nbvals;

		// Minimum entropy has 0.1 transparency. Max has 1.
		for (var i in values) {
			var y = 0.1 + (1 - 0.1) * ((values[i] - min) / (max - min));
			var addr = '0x' + res['entropy'][i]['addr'].toString(16);
			body += '<rect x="' + (inc * i).toString();
			body += '" y="0" width="' + inc.toString();
			body += '" height="' + height + '" style="fill:black;fill-opacity:';
			body += y.toString() + ';"><title>';
			body += addr + ' </title></rect>' ;

			if (i % 8 == 0) {
				body += '<text transform="matrix(1 0 0 1 ';
				body += (i * inc).toString();
				body += ' ' + (height + 15) + ')" fill="ff8888" font-family="\'Roboto\'" font-size="9">';
				body += addr + '</text>';
			}
		}

		eg.innerHTML = body;
		eg.onclick = function(e) {
			var box = eg.getBoundingClientRect();
			var pos = e.clientX - box.left;
			var i = 0 | (pos / (box.width / nbvals));
			var addr = '0x' + res['entropy'][i]['addr'].toString(16);
			seek(addr);
		};
	});
}

function onClick(a, b) {
	var h = document.getElementById(a);
	if (h) {
		h.addEventListener('click', function() {
			b();
		});
	} else {
		console.error('onclick-error', a);
	}
}

function panelHelp() {
	alert('TODO');
}

function analyzeButton() {
	function cb() {
		updateFortune();
		updateInfo();
		updateEntropy();
	}
	if (E('anal_calls').checked) {
		r2.cmd('e anal.calls=true;aac', cb);
	} else {
		r2.cmd('e anal.calls=false');
	}
	if (E('anal_prelude').checked) {
		r2.cmd('aap', cb);
	}
	if (E('anal_emu').checked) {
		r2.cmd('e asm.emu=1;aae;e asm.emu=0', cb);
	} else {
		r2.cmd('e asm.emu=false');
	}
	if (E('anal_autoname').checked) {
		r2.cmd('aan', cb);
	}
	if (E('anal_symbols').checked) {
		r2.cmd('aa', cb); // aaa or aaaa
	}
}

var twice = false;
var widgetContainer = undefined;
var updates = undefined;
var lastViews = undefined;
function ready() {
	if (twice) {
		return;
	}
	twice = true;

	updates = new UpdateManager();
	lastViews = new UpdateManager();

	// Define Widget container
	widgetContainer = new ContainerZone('content', 'ruler', 'title');
	widgetContainer.fallbackWidget(panelDisasm);
	widgetContainer.addFocusListener(updates);
	widgetContainer.addFocusListener(lastViews);

	update = function() {
		updates.apply();
	};

	lastView = function() {
		lastViews.apply();
	};

	// Defining default situation
	panelOverview();

	/* left menu */
	onClick('analyze_button', analyzeButton);
	onClick('menu_overview', panelOverview);
	onClick('menu_headers', panelHeaders);
	onClick('info_headers', panelHeaders);
	onClick('menu_disasm', panelDisasm);
	onClick('menu_debug', panelDebug);
	onClick('menu_hexdump', panelHexdump);
	onClick('menu_functions', panelFunctions);
	onClick('menu_flags', panelFlags);
	onClick('menu_search', panelSearch);
	onClick('menu_comments', panelComments);
	//onClick('menu_console', panelConsole);
	onClick('menu_script', panelScript);
	onClick('menu_help', panelHelp);

	/* left sub-menu */
	onClick('menu_project_save', saveProject);
	onClick('menu_project_delete', deleteProject);
	onClick('menu_project_close', closeProject);

	/* right menu */
	onClick('menu_seek', seek);
	//onClick('menu_console', panelConsole);
	onClick('menu_settings', panelSettings);
	onClick('menu_about', panelAbout);
	onClick('menu_mail', function() {
		window.location = 'mailto:pancake@nopcode.org';
	});

	// Set autocompletion
	var autocompletion = new Autocompletion('search', 'search_autocomplete', 'fs *;fj');
	autocompletion.setPrepareView(function() {
		// If not splitted we split the view
		if (!widgetContainer.isSplitted()) {
			widgetContainer.split(widgetContainer.Layout.VERTICAL);
		}
		panelDisasm();
	});

	// Close the drawer on click with small screens
	document.querySelector('.mdl-layout__drawer').addEventListener('click', function () {
		document.querySelector('.mdl-layout__obfuscator').classList.remove('is-visible');
		this.classList.remove('is-visible');
	}, false);
}

window.onload = ready;

document.addEventListener('DOMContentLoaded', ready, false);

document.body.onkeypress = function(e) {
	if (e.ctrlKey) {
		const keys = [
		panelConsole,
		panelDisasm,
		panelDebug,
		panelHexdump,
		panelFunctions,
		panelFlags,
		panelHeaders,
		panelSettings,
		panelSearch
		];
		if (e.charCode == 'o'.charCodeAt(0)) {
			seek();
		}
		var k = e.charCode - 0x30;
		if (k >= 0 && k < keys.length) {
			var fn = keys[k];
			if (fn) fn();
		}
	}
};

/* global keybindings are dangerous */
/*
document.body.onkeypress = function(e){
	if (e.keyCode == ':'.charCodeAt(0)) {
		statusConsole();
	}
}
*/

/* TODO
 * - add timestamp
 * - support tabs and console
 */
var statusLog = [];
var Mode = {
	LINE: 0,
	HALF: 1,
	FULL: 2
};
var Tab = {
	LOGS: 0,
	CONSOLE: 1
};
var statusMode = Mode.LINE;
var statusTimeout = null;
var statusTab = Tab.LOGS;

function setStatusbarBody() {
	function addElement(e, id) {
		var doc = document.createElement(e);
		doc.id = id;
		doc.className = id;
		return doc;
	}
	var doc;
	try {
		var statusbar = document.getElementById('tab_terminal');
		statusbar.innerHTML = '';
		statusbar.parentNode.removeChild(statusbar);
	} catch (e) {
	}
	try {
		var statusbar = document.getElementById('tab_logs');
		statusbar.innerHTML = '';
		statusbar.parentNode.removeChild(statusbar);
	} catch (e) {
	}
	switch (statusTab) {
	case Tab.LOGS:
		var parser = new DOMParser();
		var doc = document.createElement('div');
		doc.id = 'tab_logs';
		var msg = statusLog.join('<br />');
		doc.appendChild (parser.parseFromString(msg, "text/xml").documentElement);
		var statusbar = document.getElementById('statusbar_body');
		try {
		statusbar.parentNode.insertBefore (doc, statusbar);
		} catch (e ){
		//	statusbar.appendChild(doc);
		}
		console.log(statusbar);
		// return doc; //break;
		return;
	case Tab.CONSOLE:
		var doc = document.createElement('div');
		doc.id = 'tab_terminal';
		doc.appendChild(addElement('div', 'terminal'));
		doc.appendChild(addElement('div', 'terminal_output'));
		var pr0mpt = addElement('div', 'terminal_prompt');
		pr0mpt.appendChild(addElement('input', 'terminal_input'));
		doc.appendChild(pr0mpt);
		break;
	}
	if (doc !== undefined) {
		/* initialize terminal if needed */
		var statusbar = document.getElementById('statusbar');
		var terminal = document.getElementById('terminal');
		if (!terminal) {
			statusbar.parentNode.insertBefore (doc, statusbar);
			if (statusTab === Tab.CONSOLE) {
				terminal_ready ();
			}
		}
	}
}

function statusMessage(x, t) {
	var statusbar = document.getElementById('statusbar');
	if (x) {
		statusLog.push(x);
	}
	if (statusMode === Mode.LINE) {
		statusbar.innerHTML = x;
		if (statusTimeout !== null) {
			clearTimeout(statusTimeout);
			statusTimeout = null;
		}
		if (t !== undefined) {
			statusTimeout = setTimeout(function() {
				statusMessage('&nbsp;');
			}, t * 1000);
		}
	} else {
		setStatusbarBody();
	}
}

function statusToggle() {
	var statusbar = document.getElementById('statusbar');
	var container = document.getElementById('container');
	if (statusMode == Mode.HALF) {
		statusTab = Tab.LOGS;
		statusMode = Mode.LINE;
		statusbar.innerHTML = '&nbsp;';
		try {
			statusbar.parentNode.classList.remove('half');
			statusbar.parentNode.classList.remove('full');
			container.classList.remove('sbIsHalf');
			container.classList.remove('sbIsFull');
		} catch (e) {
		}
		setStatusbarBody();
	} else {
		statusMode = Mode.HALF;
		try {
			statusbar.parentNode.classList.remove('full');
			container.classList.remove('sbIsFull');
		} catch (e) {
		}
		statusbar.parentNode.classList.add('half');
		container.classList.add('sbIsHalf');
		//setStatusbarBody();
	}
}

function statusNext() {
	var statusbar = document.getElementById('statusbar');
	var container = document.getElementById('container');
	switch (statusMode) {
	case Mode.LINE:
		statusMode = Mode.HALF;
		try {
			statusbar.parentNode.classList.remove('full');
			container.classList.remove('sbIsFull');
		} catch (e) {
		}
		statusbar.parentNode.classList.add('half');
		container.classList.add('sbIsHalf');
		break;
	case Mode.HALF:
		statusMode = Mode.FULL;
		statusbar.parentNode.classList.add('full');
		container.classList.add('sbIsFull');
		/* do not clear the terminal */
		return;
		break;
	case Mode.FULL:
		statusMode = Mode.LINE;
		statusTab = Tab.LOGS;
		statusbar.innerHTML = '';
		try {
			var statusbar = document.getElementById('statusbar');
			var container = document.getElementById('container');
			statusbar.parentNode.classList.remove('half');
			statusbar.parentNode.classList.remove('full');
			container.classList.remove('sbIsHalf');
			container.classList.remove('sbIsFull');
		} catch (e) {
		}
		break;
	}
	setStatusbarBody();
}

function statusConsole() {
	var statusbar = document.getElementById('statusbar');
	var container = document.getElementById('container');
	if (statusMode === Mode.LINE) {
		statusMode = Mode.HALF;
		try {
			statusbar.parentNode.classList.remove('full');
			container.classList.remove('sbIsFull');
		} catch (e) {
		}
		try {
			statusbar.parentNode.classList.add('half');
			container.classList.add('sbIsHalf');
		} catch (e) {
		}
	}
	if (statusTab == Tab.CONSOLE) {
		statusTab = Tab.LOGS;

	} else {
		statusTab = Tab.CONSOLE;
	}
	setStatusbarBody();
}

function statusFullscreen() {
	var statusbar = document.getElementById('statusbar');
	var container = document.getElementById('container');
	if (statusMode == Mode.FULL) {
		statusMode = Mode.HALF;
		try {
			statusbar.parentNode.classList.remove('full');
			container.classList.remove('sbIsFull');
		} catch (e) {
		}
		statusbar.parentNode.classList.add('half');
		container.classList.add('sbIsHalf');
	} else {
		statusMode = Mode.FULL;
		try {
			statusbar.parentNode.classList.remove('half');
			container.classList.remove('sbIsHalf');
		} catch (e) {
			/* do nothing */
		}
		statusbar.parentNode.classList.add('full');
		container.classList.add('sbIsFull');
	}
}


function addButton(label, callback) {
	var a = document.createElement('a');
	a.href = 'javascript:'+callback+'()';
	a.innerHTML = label;
	return a;
}

function initializeStatusbarTitle() {
return;
	var title = document.getElementById('statusbar_title');
	var div = document.createElement('div');
	title.class = 'statusbar_title';
	title.id = 'statusbar_title';
	div.className = 'statusbar_title';
	div.style.textAlign = 'right';
	div.appendChild (addButton ('v ', 'statusToggle'));
	div.appendChild (addButton ('^ ', 'statusFullscreen'));
	div.appendChild (addButton ('$ ', 'statusConsole'));
	div.appendChild (addButton ('> ', 'statusBarAtRight'));
	title.parentNode.replaceChild (div, title);
	// title.parentNode.insertBefore (div, title);
}

function statusInitialize() {
	initializeStatusbarTitle();
	var statusbar = document.getElementById('statusbar');
	statusbar.innerHTML = '';
	statusbar.parentNode.addEventListener('click', function() {
		if (statusMode == Mode.LINE) {
			statusToggle();
		}
	});
	statusMessage('Loading webui...', 2);
}

statusInitialize();

/* --- terminal.js --- */
function submit(cmd) {
	var output = document.getElementById('terminal_output');
	var input = document.getElementById('terminal_input');
	if (!input || !output) {
		console.error('No terminal_{input|output} found');
		return;
	}
	if (cmd === 'clear') {
		output.innerHTML = '';
		input.value = '';
		return;
	}
	r2.cmd(cmd, function(res) {
		res += '\n';
		output.innerHTML += ' > '
			+ cmd + '\n' + res;
		input.value = '';
		var bar = document.getElementById('statusbar_scroll');
		bar.scrollTop = bar.scrollHeight;
	});
}

function terminal_ready() {
	r2.cmd("e scr.color=true");
	var input = document.getElementById('terminal_input');
	if (!input) {
		console.error('Cannot find terminal_input');
		return;
	}
	input.focus();
	input.onkeypress = function(e){
		if (e.keyCode == 13) {
			submit(input.value);
		}
	}
}

/* --- terminal.js --- */

/**
 * Handling DataTables with jQuery plugin
 *
 * @param {Array} cols - List of columns, add "+" at beginning to specify a clickable field (seek method)
 * @param {Array} nonum - List of booleans, set true if non-numeric
 * @param {String} id - Id (DOM) of the current table, internal usage for DataTable plugin
 */
function Table(cols, nonum, id) {
	this.cols = cols;
	this.nonum = nonum;
	this.clickableOffset = [];
	this.id = id || false;

	this.init();
}

Table.prototype.init = function() {
	this.root = document.createElement('table');
	this.root.className = 'mdl-data-table mdl-data-table--selectable mdl-shadow--2dp';
	if (this.root.id !== false) {
		this.root.id = this.id;
	}

	this.thead = document.createElement('thead');
	this.root.appendChild(this.thead);
	this.tbody = document.createElement('tbody');
	this.root.appendChild(this.tbody);

	var tr = document.createElement('tr');
	this.thead.appendChild(tr);

	for (var c in this.cols) {
		if (this.cols[c][0] == '+') {
			this.clickableOffset[c] = true;
			this.cols[c] = this.cols[c].substr(1);
		} else {
			this.clickableOffset[c] = false;
		}

		var th = document.createElement('th');
		th.appendChild(document.createTextNode(this.cols[c]));
		if (this.nonum[c]) {
			th.className = 'mdl-data-table__cell--non-numeric';
		}
		tr.appendChild(th);
	}
};

Table.prototype.addRow = function(cells) {
	var tr = document.createElement('tr');
	this.tbody.appendChild(tr);

	for (var i = 0 ; i < cells.length ; i++) {
		var td = document.createElement('td');
		if (this.clickableOffset[i]) {
			td.innerHTML = clickableOffsets(cells[i]);
		} else {
			td.appendChild(document.createTextNode(cells[i]));
		}
		tr.appendChild(td);
	}
};

Table.prototype.insertInto = function(node) {
	node.appendChild(this.root);
	if (this.id !== false) {
		$('#' + this.id).DataTable();
	}
};


/**
 * Legacy methods, extracted from main JS
 */

function uiTableBegin(cols, id) {
	var out = '';
	var id = id || '';
	console.log(id.substr(1));
	out += '<table id="'+id.substr(1)+'" style="margin-left:10px" class="mdl-data-table mdl-js-data-table mdl-data-table--selectable mdl-shadow--2dp">';
	//out += '<table class="mdl-data-table mdl-js-data-table mdl-data-table--selectable">';

	out += '  <thead> <tr>';

	var type;
	for (var i in cols) {
		var col = cols[i];
		if (col[0] == '+') {
			col = col.substring(1);
			type = '';
		} else {
			type = ' class="mdl-data-table__cell--non-numeric"';
		}
		out += '<th' + type + '>' + col + '</th>';
	}
	out += '</tr> </thead> <tbody>';
	return out;
}

function uiTableRow(cols) {
	var out = '<tr>';
	for (var i in cols) {
		var col = cols[i];
		if (!col) continue;
		if (col[0] == '+') {
			col = clickableOffsets(col.substring(1));
			type = '';
		} else {
			type = ' class="mdl-data-table__cell--non-numeric"';
		}
		out += '<td' + type + '>' + col + '</td>';
	}
	return out + '</tr>';
}

function uiTableEnd() {
	return '</tbody> </table>';
}

function UpdateManager() {
	this.updateMethods = [{}, {}];
	this.currentFocus = undefined;
};

UpdateManager.prototype.registerMethod = function(offset, method) {
	this.updateMethods[offset] = method;
};

UpdateManager.prototype.focusHasChanged = function(offset) {
	this.currentFocus = offset;
};

UpdateManager.prototype.apply = function() {
	if (typeof this.currentFocus === 'undefined') {
		return;
	}
	this.updateMethods[this.currentFocus]();
};

function Widget(name, identifier) {
	this.name = name;
	this.identifier = identifier;

	if (typeof identifier !== 'undefined') {
		this.DOMWrapper = document.getElementById(identifier);
	}
}

Widget.prototype.binding = function(domElement) {
	this.DOMWrapper = domElement;
	if (typeof this.content !== 'undefined') {
		this.DOMWrapper.innerHTML = this.content;
	}
};

Widget.prototype.setHTMLContent = function(content) {
	this.content = content;
};

Widget.prototype.getName = function() {
	return this.name;
};

Widget.prototype.getIdentifier = function() {
	return this.identifier;
};

Widget.prototype.setOffset = function(offset) {
	this.offset = offset;
};

Widget.prototype.getOffset = function() {
	return this.offset;
};

/**
 * Identify the special case where the content is already here, in the page
 */
Widget.prototype.isAlreadyThere = function() {
	return (typeof this.identifier !== 'undefined');
};

Widget.prototype.setDark = function() {
	this.DOMWrapper.style.backgroundColor = 'rgb(32, 32, 32)';
};
function panelOverview() {
	var widget = widgetContainer.getWidget('Overview');
	var c = widgetContainer.getWidgetDOMWrapper(widget);
	updates.registerMethod(widget.getOffset(), panelSettings);

	var out = '<div class="mdl-grid demo-content">';
	out += '<div class="demo-graphs mdl-shadow--2dp mdl-color--white mdl-cell mdl-cell--8-col">';
	out += '	<div id="info"> </div>';
	out += '	<br />';
	out += '	<a id="info_headers" class="mdl-buton mdl-js-buttom mdl-js-ripple-effect" style="cursor:pointer">read more...</a>';
	out += '	<h3>Entropy</h3>';
	out += '		<svg fill="currentColor" viewBox="0 0 500 80" id="entropy-graph"></svg>';
	out += '</div>';

	out += '<div class="demo-cards mdl-cell mdl-cell--4-col mdl-cell--8-col-tablet mdl-grid mdl-grid--no-spacing">';
	out += '	<div class="demo-updates mdl-card mdl-shadow--2dp mdl-cell mdl-cell--4-col mdl-cell--4-col-tablet mdl-cell--12-col-desktop">';
	out += '		<div class="mdl-card__title mdl-card--expand mdl-color--teal-300">';
	out += '			<h2 class="mdl-card__title-text">Fortunes</h2>';
	out += '		</div>';
	out += '		<div class="mdl-card__supporting-text mdl-color-text--grey-600" id="fortune">';
	out += '			Always use r2 from git';
	out += '		</div>';
	out += '		<div class="mdl-card__actions mdl-card--border">';
	out += '			<a href="javascript:updateFortune()" class="mdl-button mdl-js-button mdl-js-ripple-effect">Next</a>';
	out += '		</div>';
	out += '	</div>';
	out += '	<div class="demo-separator mdl-cell--1-col"></div>';
	out += '	<div class="demo-options mdl-card mdl-color--teal-300 mdl-shadow--2dp mdl-cell mdl-cell--4-col mdl-cell--3-col-tablet mdl-cell--12-col-desktop">';
	out += '		<div class="mdl-card__supporting-text mdl-color-grey-600">';
	out += '			<h3 class="mdl-cart__title-text">Analysis Options</h3>';
	out += '			<ul>';
	out += '				<li>';
	out += '					<label for="anal_symbols" class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect">';
	out += '						<input type="checkbox" id="anal_symbols" class="mdl-checkbox__input" />';
	out += '						<span id="anal_symbols" class="mdl-checkbox__label">Analyze symbols</span>';
	out += '					</label>';
	out += '				</li>';
	out += '				<li>';
	out += '					<label for="anal_calls" class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect">';
	out += '						<input id="anal_calls" type="checkbox" class="mdl-checkbox__input" />';
	out += '						<span class="mdl-checkbox__label">Analyze calls</span>';
	out += '					</label>';
	out += '				</li>';
	out += '				<li>';
	out += '					<label for="anal_emu" class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect">';
	out += '						<input id="anal_emu" type="checkbox" class="mdl-checkbox__input" />';
	out += '						<span class="mdl-checkbox__label">Emulate code</span>';
	out += '					</label>';
	out += '				</li>';
	out += '				<li>';
	out += '					<label for="anal_prelude" class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect">';
	out += '						<input id="anal_prelude" type="checkbox" class="mdl-checkbox__input" />';
	out += '						<span class="mdl-checkbox__label">Find preludes</span>';
	out += '					</label>';
	out += '				</li>';
	out += '				<li>';
	out += '					<label for="anal_autoname" class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect">';
	out += '						<input type="checkbox" id="anal_autoname" class="mdl-checkbox__input" />';
	out += '						<span id="anal_autoname" class="mdl-checkbox__label">Autoname fcns</span>';
	out += '					</label>';
	out += '				</li>';
	out += '			</ul>';
	out += '		</div>';
	out += '		<div class="mdl-card__actions mdl-card--border">';
	out += '			<a href="#" id="analyze_button" class="mdl-button mdl-js-button mdl-js-ripple-effect mdl-color--blue-grey-50 mdl-color-text--blue-greu-50">Analyze</a>';
	out += '			<div class="mdl-layout-spacer"></div>';
	out += '			<i class="material-icons">room</i>';
	out += '		</div>';
	out += '	</div>';
	out += '</div>';
	out += '<div class="demo-charts mdl-color--white mdl-shadow--2dp mdl-cell mdl-cell--12-col mdl-grid">';
	out += '	<svg fill="currentColor" width="200px" height="200px" viewBox="0 0 1 1" class="demo-chart mdl-cell mdl-cell--4-col mdl-cell--3-col-desktop clickable" onclick="panelDisasm();seek(\'entry0\');" title="Go to disassembly">';
	out += '		<use xlink:href="#piechart" mask="url(#piemask)" />';
	out += '		<text x="0.3" y="0.2" font-family="Roboto" font-size="0.1" fill="#888" text-anchor="top" dy="0.1">code</text>';
	out += '		<text x="0.5" y="0.5" font-family="Roboto" font-size="0.3" fill="#888" text-anchor="middle" dy="0.1">82<tspan font-size="0.2" dy="-0.07">%</tspan></text>';
	out += '	</svg>';
	out += '	<svg fill="currentColor" width="200px" height="200px" viewBox="0 0 1 1" class="demo-chart mdl-cell mdl-cell--4-col mdl-cell--3-col-desktop clickable" onclick="panelHexdump();seek(\'0x00\');" title="Go to hexdump">';
	out += '		<use xlink:href="#piechart2" mask="url(#piemask)" />';
	out += '		<text x="0.3" y="0.2" font-family="Roboto" font-size="0.1" fill="#888" text-anchor="top" dy="0.1">data</text>';
	out += '		<text x="0.5" y="0.5" font-family="Roboto" font-size="0.3" fill="#888" text-anchor="middle" dy="0.1">22<tspan dy="-0.07" font-size="0.2">%</tspan></text>';
	out += '	</svg>';
	out += '	<svg fill="currentColor" width="200px" height="200px" viewBox="0 0 1 1" class="demo-chart mdl-cell mdl-cell--4-col mdl-cell--3-col-desktop clickable" onclick="panelStrings()" title="Go to strings">';
	out += '		<use xlink:href="#piechart" mask="url(#piemask)" />';
	out += '		<text x="0.3" y="0.2" font-family="Roboto" font-size="0.1" fill="#888" text-anchor="top" dy="0.1">strings</text>';
	out += '		<text x="0.5" y="0.5" font-family="Roboto" font-size="0.3" fill="#888" text-anchor="middle" dy="0.1">4<tspan dy="-0.07" font-size="0.2">%</tspan></text>';
	out += '	</svg>';
	out += '	<svg fill="currentColor" width="200px" height="200px" viewBox="0 0 1 1" class="demo-chart mdl-cell mdl-cell--4-col mdl-cell--3-col-desktop clickable" onclick="panelFunctions()" title="Go to functions">';
	out += '		<use xlink:href="#piechart" mask="url(#piemask)" />';
	out += '		<text x="0.3" y="0.2" font-family="Roboto" font-size="0.1" fill="#888" text-anchor="top" dy="0.1">functions</text>';
	out += '		<text x="0.5" y="0.5" font-family="Roboto" font-size="0.3" fill="#888" text-anchor="middle" dy="0.1">82<tspan dy="-0.07" font-size="0.2">%</tspan></text>';
	out += '	</svg>';
	out += '</div>';
	out += '</div>';

	c.innerHTML = out;

	updateFortune();
	updateInfo();
	updateEntropy();
}
