function ActionListener(fct) {
	this.cmd = fct;
	this.actions = {};
};

ActionListener.prototype.registerLocalAction = function(widgetName, callback) {
	this.actions[widgetName] = callback;
};

ActionListener.prototype.applyGlobal = function(args) {
	this.cmd(args);
};

ActionListener.prototype.apply = function(args) {
	this.applyGlobal(args);
	if (typeof args !== 'undefined') {
		var currentlyDrawn = widgetContainer.getCurrentlyDrawn();
		for (var i = 0 ; i < currentlyDrawn.length ; i++) {
			var localAction = this.actions[currentlyDrawn[i]];
			if (typeof localAction !== 'undefined') {
				localAction(args);
			}
		}
	}
};

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

function BlockNavigator() {

}

BlockNavigator.prototype.Dir = {
	BEFORE: -1,
	CURRENT: 0,
	AFTER: 1
};

BlockNavigator.prototype.Status = {
	LAUNCHED: 0,
	COMPLETED: 1
};

BlockNavigator.prototype.init = function() {
	if (typeof this.providerWorker === 'undefined') {
		console.log('provider worker should be defined');
		return;
	}

	this.configureWorker_();
};

BlockNavigator.prototype.configureWorker_ = function() {
	var _this = this;
	this.providerWorker.onmessage = function(e) {
		if (e.data.dir === _this.Dir.CURRENT) {
			if (typeof _this.curChunk.data.callback !== 'undefined') {
				for (var i = 0 ; i < _this.curChunk.data.callback.length ; i++) {
					_this.curChunk.data.callback[i](e.data);
				}
			}
			_this.curChunk.data = e.data;
			_this.curChunk.data.status = _this.Status.COMPLETED;
		} else {
			var dir = (e.data.dir === _this.Dir.BEFORE) ? 'prev' : 'next';

			var item = _this.curChunk;
			while (typeof item[dir] !== 'undefined') {
				item = item[dir];
				if (item.data.offset === e.data.offset) {
					break;
				}
			}

			if (item === _this.curChunk) {
				console.log('Error, history corrupted');
				return;
			}

			if (typeof item.data.callback !== 'undefined') {
				for (var i = 0 ; i < item.data.callback.length ; i++) {
					item.data.callback[i](e.data);
				}
			}

			item.data = e.data;
			item.data.status = _this.Status.COMPLETED;
		}
	};
};

BlockNavigator.prototype.reset = function() {
	this.curChunk = undefined;
};

BlockNavigator.prototype.go = function(where) {
	var goNext = (where === this.Dir.AFTER);
	var dir = (goNext) ? 'next' : 'prev';
	var howMany = this.gap;

	if (typeof this.curChunk[dir] !== 'undefined') {
		this.curChunk = this.curChunk[dir];
		this.currentOffset = this.curChunk.data.offset;
		// Should check (or not?) for negative offset
	} else {
		this.currentOffset = this.currentOffset + where * this.gap;

		var req = {
			dir: where,
			offset: this.currentOffset,
			status: this.Status.LAUNCHED,
			callback: []
		};

		if (this.currentOffset < 0) {
			req.substract = this.currentOffset * -1;
			req.offset = 0;
			this.currentOffset = 0;
		}

		var newChunk = {
			data: req,
			prev: (goNext) ? this.curChunk : undefined,
			next: (!goNext) ? this.curChunk : undefined
		};

		this.curChunk[dir] = newChunk;
		this.curChunk = newChunk;

		this.providerWorker.postMessage(req);
	}
};

BlockNavigator.prototype.get = function(which, callback, force) {
	var dir = (which === this.Dir.BEFORE) ? 'prev' : 'next';

	var item;
	if (which === this.Dir.CURRENT) {
		item = this.curChunk;
	} else {
		if (typeof this.curChunk === 'undefined') {
			item = undefined;
		} else {
			item = this.curChunk[dir];
		}
	}

	// If there is a miss (when we start)
	if (typeof item === 'undefined') {
		if (which === this.Dir.CURRENT) {
			req = {
				dir: this.Dir.CURRENT,
				offset: this.currentOffset,
				status: this.Status.LAUNCHED,
				callback: []
			};
			this.curChunk = {
				data: req,
				prev: undefined,
				next: undefined
			};
			item = this.curChunk;
			this.providerWorker.postMessage(req);
		} else {
			req = {
				dir: which,
				offset: this.currentOffset + (which * this.gap),
				status: this.Status.LAUNCHED,
				callback: []
			};
			this.curChunk[dir] = {
				data: req,
				prev: (which === this.Dir.AFTER) ? this.curChunk : undefined,
				next: (which === this.Dir.BEFORE) ? this.curChunk : undefined
			};
			item = this.curChunk[dir];
			this.providerWorker.postMessage(req);
		}
	} else if (force === true) {
		item.data.status = this.Status.LAUNCHED;
		this.providerWorker.postMessage(item.data);
	}

	// We infer the data is here
	if (item.data.status !== this.Status.LAUNCHED) {
		return callback(item.data);
	} else { // Data isn't here, we deffer our callback
		if (typeof item.data.callback === 'undefined') {
			item.data.callback = [];
		}
		item.data.callback.push(callback);
		return;
	}
};

BlockNavigator.prototype.isInside_ = function(chunk, offset) {
	var start = chunk.offset;
	var end = start + this.gap;
	return (start <= offset && end >= offset);
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

	this.setFocus(0);
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

/**
 * Tell if the widget is currently displayed (careful to case sensitivity)
 */
ContainerZone.prototype.getCurrentlyDrawn = function() {
	var list = [];
	for (var i = 0 ; i < this.populatedWidgets.length ; i++) {
		list.push(this.populatedWidgets[i].name);
	}
	return list;
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

var seekAction = new ActionListener(function(x) {
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
});

var seek = function(x) {
	return seekAction.apply(x);
};

function analyze() {
	r2.cmd('af', function() {
		panelDisasm();
	});
}

function notes() {
	var widget = widgetContainer.getWidget('Notes');
	var dom = widgetContainer.getWidgetDOMWrapper(widget);

	var out = '<br />' + uiButton('javascript:panelComments()', '&lt; Comments');
	out += '<br /><br /><textarea rows=32 style="width:100%"></textarea>';
	c.innerHTML = out;
}

function setFlagspace(fs) {
	if (!fs) {
		fs = prompt('name');
	}
	if (!fs) {
		return;
	}
	r2.cmd('fs ' + fs, function() {
		flagspaces();
	});
}

function renameFlagspace(fs) {
	if (!fs) {
		fs = prompt('name');
	}
	if (!fs) {
		return;
	}
	r2.cmd('fsr ' + fs, function() {
		flagspaces();
	});
}

function delFlagspace(fs) {
	if (!fs) {
		fs = '.';
	}
	if (!fs) {
		return;
	}
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
				if (selected) {
					a += '<font color=\'red\'>' + line[3] + '</font>';
				} else {
					a += line[3];
				}
				a += '</a>';
				body += uiTableRow(['+' + line[1], a]);
			}
		}
		body += uiTableEnd();
		c.innerHTML += body;
	});
}

function analyzeSymbols() {
	statusMessage('Analyzing symbols...');
	r2.cmd('aa', function() {
		statusMessage('done');
		update();
	});
}
function analyzeRefs() {
	statusMessage('Analyzing references...');
	r2.cmd('aar', function() {
		statusMessage('done');
		update();
	});
}
function analyzeCalls() {
	statusMessage('Analyzing calls...');
	r2.cmd('aac', function() {
		statusMessage('done');
		update();
	});
}
function analyzeFunction() {
	statusMessage('Analyzing function...');
	r2.cmd('af', function() {
		statusMessage('done');
		update();
	});
}
function analyzeNames() {
	statusMessage('Analyzing names...');
	r2.cmd('.afna @@ fcn.*', function() {
		statusMessage('done');
		update();
	});
}

function panelAbout() {
	r2.cmd('?V', function(version) {
		alert('radare2 material webui by --pancake @ 2015-2016\n\n' + version.trim());
	});
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
		var table = new Table(
			['+Address', 'Name', '+Size', '+CC'],
			[false, true, false, false],
			'functionTable');

		var lines = d.split(/\n/); //clickableOffsets (d).split (/\n/);
		for (var i in lines) {
			var items = lines[i].match(/^(0x[0-9a-f]+)\s+([0-9]+)\s+([0-9]+(\s+\-&gt;\s+[0-9]+)?)\s+(.+)$/);
			if (items !== null) {
				table.addRow([items[1], items[5], items[2], items[3]]);
			}
		}
		table.insertInto(c);
	});

}

var lastConsoleOutput = '';

function runCommand(text) {
	if (!text) {
		text = document.getElementById('input').value;
	}
	r2.cmd(text, function(d) {
		lastConsoleOutput = '\n' + d;
		document.getElementById('output').innerHTML = lastConsoleOutput;
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

function panelConsole() {
	var widget = widgetContainer.getWidget('Console');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	updates.registerMethod(widget.getOffset(), panelConsole);

	c.innerHTML = '<br />';
	var common = 'onkeypress=\'consoleKey()\' class=\'mdl-card--expand mdl-textfield__input\' id=\'input\'';
	if (inColor) {
		c.style.backgroundColor = '#202020';
		var styles = 'position:fixed;padding-left:10px;top:4em;height:1.8em;color:white';
		c.innerHTML += '<input style=\'' + styles + '\' ' + common + ' />';
		//c.innerHTML += uiButton('javascript:runCommand()', 'Run');
		c.innerHTML += '<div id=\'output\' class=\'pre\' style=\'color:white !important\'><div>';
	} else {
		c.style.backgroundColor = '#f0f0f0';
		c.innerHTML += '<input style=\'color:black\' ' + common + '/>';
		c.innerHTML += uiButton('javascript:runCommand()', 'Run');
		c.innerHTML += '<div id=\'output\' class=\'pre\' style=\'color:black!important\'><div>';
	}
	document.getElementById('output').innerHTML = lastConsoleOutput;
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
	if (!text) {
		text = document.getElementById('search_input').value;
	}
	r2.cmd('"/c ' + text + '"', function(d) {
		document.getElementById('search_output').innerHTML = clickableOffsets(d);
	});
}
function runSearchString(text) {
	if (!text) {
		text = document.getElementById('search_input').value;
	}
	r2.cmd('/ ' + text, function(d) {
		document.getElementById('search_output').innerHTML = clickableOffsets(d);
	});
}
function runSearchROP(text) {
	if (!text) {
		text = document.getElementById('search_input').value;
	}
	r2.cmd('"/R ' + text + '"', function(d) {
		document.getElementById('search_output').innerHTML = clickableOffsets(d);
	});
}

function runSearch(text) {
	if (!text) {
		text = document.getElementById('search_input').value;
	}
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
	var indented = /* NOT DEFINED js_beautify*/ (str);
	document.getElementById('script').value = indented;
	localStorage.script = indented;
}

function runScript() {
	var str = document.getElementById('script').value;
	localStorage.script = str;
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
	var style = 'background-color:white !important;padding-left:10px;top:3.5em;height:1.8em;color:white';
	var classes = 'mdl-card--expand mdl-textfield__input';
	var out = '<br />';
	out += '<input style=\'' + style + '\' onkeypress=\'searchKey()\' class=\'' + classes + '\' id=\'search_input\'/>';
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

		var table = new Table(
			['+Offset', '+Size', 'Name'],
			[true, true, false],
			'flagsTable');

		var lines = d.split(/\n/); //clickableOffsets (d).split (/\n/);
		for (var i in lines) {
			var line = lines[i].split(/ /);
			if (line.length >= 3) {
				table.addRow([line[0], line[1], line[2]]);
			}
		}
		table.insertInto(c);
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

	c.style.overflow = 'none';
	var color = inColor ? 'white' : 'black';
	var cl = 'mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect ';
	cl += 'mdl-color--accent mdl-color-text--accent-contrast';
	c.innerHTML = '<br />';
	c.innerHTML += '&nbsp;<a href="javascript:panelDisasm()" class="' + cl + '">&lt; INFO</a> <h3 color=white></h3>';
	var tail = inColor ? '@e:scr.color=1,scr.html=1' : '';
	r2.cmd('pdr' + tail, function(d) {
		c.innerHTML += '<pre style=\'color:' + color + '\'>' + d + '<pre>';
	});
}

function pdtext() {
	var widget = widgetContainer.getWidget('Function');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	c.style.overflow = 'none';
	var color = inColor ? 'white' : 'black';
	var cl = 'mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect ';
	cl += 'mdl-color--accent mdl-color-text--accent-contrast';
	c.innerHTML = '<br />';
	c.innerHTML += '&nbsp;<a href="javascript:panelDisasm()" class="' + cl + '">&lt; INFO</a> <h3 color=white></h3>';
	var tail = inColor ? '@e:scr.color=1,scr.html=1,asm.lineswidth=0' : '@e:asm.lineswidth=0';
	r2.cmd('e scr.color=1;s entry0;s $S;pD $SS;e scr.color=0', function(d) {
		d = clickableOffsets(d);
		c.innerHTML += '<pre style=\'color:' + color + '\'>' + d + '<pre>';
	});
}

function pdf() {
	var widget = widgetContainer.getWidget('Function');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	c.style.overflow = 'none';
	var color = inColor ? 'white' : 'black';
	var cl = 'mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect ';
	cl += 'mdl-color--accent mdl-color-text--accent-contrast';
	c.innerHTML = '<br />';
	c.innerHTML += '&nbsp;<a href="javascript:panelDisasm()" class="' + cl + '">&lt; INFO</a> <h3 color=white></h3>';
	var tail = inColor ? '@e:scr.color=1,scr.html=1,asm.lineswidth=0' : '@e:asm.lineswidth=0';
	r2.cmd('pdf' + tail, function(d) {
		c.innerHTML += '<pre style=\'color:' + color + '\'>' + d + '<pre>';
	});
}

function decompile() {
	var widget = widgetContainer.getWidget('Decompile');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	c.style.overflow = 'none';
	var color = inColor ? 'white' : 'black';
	var cl = 'mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect ';
	cl += 'mdl-color--accent mdl-color-text--accent-contrast';
	c.innerHTML = '<br />';
	c.innerHTML += '&nbsp;<a href="javascript:panelDisasm()" class="' + cl + '">&lt; INFO</a> <h3 color=white></h3>';
	var tail = inColor ? '@e:scr.color=1,scr.html=1' : '';
	r2.cmd('pdc' + tail, function(d) {
		c.innerHTML += '<pre style=\'color:' + color + '\'>' + d + '<pre>';
	});
}

function graph() {
	var widget = widgetContainer.getWidget('Graph');
	widget.setDark();
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	c.style.overflow = 'auto';
	var color = inColor ? 'white' : 'black';
	var cl = 'mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect ';
	cl += 'mdl-color--accent mdl-color-text--accent-contrast';
	c.innerHTML = '<br />&nbsp;<a href="javascript:panelDisasm()" class="' + cl + '">&lt; INFO</a>';
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

	// Loading configuration from localStorage (see panelSettings)
	applyConf();

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
	document.querySelector('.mdl-layout__drawer').addEventListener('click', function() {
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
		panelOverview,
		panelSettings,
		panelSearch
		];
		if (e.charCode == 'o'.charCodeAt(0)) {
			seek();
		}
		var k = e.charCode - 0x30;
		if (k >= 0 && k < keys.length) {
			var fn = keys[k];
			if (fn) {
				fn();
			}
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

function RadareInfiniteBlock() {

}

/**
 * Define where we should process
 */
RadareInfiniteBlock.prototype.Dir = {
	BEFORE: -1,
	CURRENT: 0,
	AFTER: 1
};

/**
 * Helper to delay drawing
 */
RadareInfiniteBlock.prototype.getCurChunk = function() {
	return this.curChunk;
};

/**
 * Helper for dynamic callback at first drawing
 * Allows to place the scroll on current chunk.
 */
RadareInfiniteBlock.prototype.getFirstElement = function() {
	return this.firstElement;
};

/**
 * Load the *new* initial offset from the "s" value
 */
RadareInfiniteBlock.prototype.refreshInitialOffset = function() {
	var _this = this;
	r2.cmd('s', function(offset) {
		_this.initialOffset = parseInt(offset, 16);
	});
};

/**
 * Gather data and set event to configure infinite scrolling
 */
RadareInfiniteBlock.prototype.defineInfiniteParams = function(trigger) {
	var height = (this.container.getBody().offsetHeight === 0) ? 800 : this.container.getBody().offsetHeight;
	this.howManyLines = Math.floor((height / this.lineHeight) * this.infineHeightProvisioning);

	var infiniteScrolling = new InfiniteScrolling(
		this.container.getBody(),
		3, /* before, current, after */
		(typeof trigger !== 'undefined') ? trigger : 0.20 /* when there less than 1/5 visible */
	);

	var _this = this;
	infiniteScrolling.setTopEvent(function(pos, endCallback) {
		_this.nav.go(_this.nav.Dir.BEFORE);
		_this.infiniteDrawingContent(_this.Dir.BEFORE, pos, endCallback);
	});

	infiniteScrolling.setBottomEvent(function(pos, endCallback) {
		_this.nav.go(_this.nav.Dir.AFTER);
		_this.infiniteDrawingContent(_this.Dir.AFTER, pos, endCallback);
	});
};

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

function E(x) {
	return document.getElementById(x);
}

function encode(r) {
	return r.replace(/[\x26\x0A\<>'"]/g, function(r) { return '&#' + r.charCodeAt(0) + ';';});
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

function uiButton(href, label, type) {
	var classes = 'mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect ';
	classes += 'mdl-color--accent mdl-color-text--accent-contrast';
	if (type == 'active') {
		var st = 'style="background-color:#f04040 !important"';
		return '&nbsp;<a href="' + href.replace(/"/g, '\'') + '" class="' + classes + '" ' + st + '>' + label + '</a>';
	}
	return '&nbsp;<a href="' + href.replace(/"/g, '\'') + '" class="' + classes + '">' + label + '</a>';
}

function uiCheckList(grp, id, label) {
	var output = '<li>';
	ouput += '<label for="' + grp + '" class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect">';
	ouput += '<input type="checkbox" id="' + id + '" class="mdl-checkbox__input" />';
	ouput += '<span class="mdl-checkbox__label">' + label + '</span>';
	ouput += '</label></li>';

	return output;
}

var comboId = 0;
function uiCombo(d) {
	var funName = 'combo' + (++comboId);
	var fun = funName + ' = function(e) {';
	fun += ' var sel = document.getElementById("opt_' + funName + '");';
	fun += ' var opt = sel.options[sel.selectedIndex].value;';
	fun += ' switch (opt) {';
	for (var a in d) {
		fun += 'case "' + d[a].name + '": ' + d[a].js + '(' + d[a].name + ');break;';
	}
	fun += '}}';
	// CSP violation here
	eval(fun);
	var out = '<select id="opt_' + funName + '" onchange="' + funName + '()">';
	for (var a in d) {
		var def = (d[a].default) ? ' default' : '';
		out += '<option' + def + '>' + d[a].name + '</option>';
	}
	out += '</select>';
	return out;
}

/**
 * Add a switch, with a name "label", define default state by isChecked
 * callbacks are bound when un-checked.
 */
var idSwitch = 0;
function uiSwitch(dom, name, isChecked, onChange) {
	var id = 'switch-' + (++idSwitch);

	var label = document.createElement('label');
	label.className = 'mdl-switch mdl-js-switch mdl-js-ripple-effect';
	label.for = id;
	dom.appendChild(label);

	var input = document.createElement('input');
	input.type = 'checkbox';
	input.className = 'mdl-switch__input';
	input.checked = isChecked;
	input.id = id;
	label.appendChild(input);

	input.addEventListener('change', function(evt) {
		onChange(name, evt.target.checked);
	});

	var span = document.createElement('span');
	span.className = 'mdl-switch__label';
	span.innerHTML = name;
	label.appendChild(span);
}

function uiActionButton(dom, action, label) {
	var button = document.createElement('a');
	button.href = '#';
	button.innerHTML = label;
	button.addEventListener('click', action);
	dom.appendChild(button);

	var classes = 'mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect ';
	classes += 'mdl-color--accent mdl-color-text--accent-contrast';
	button.className = classes;
	button.style.margin = '3px';
}

var selectId = 0;
function uiSelect(dom, name, list, defaultOffset, onChange) {
	var id = 'select-' + (++selectId);

	var div = document.createElement('div');
	div.className = 'mdl-selectfield mdl-js-selectfield mdl-selectfield--floating-label';
	dom.appendChild(div);

	var select = document.createElement('select');
	select.className = 'mdl-selectfield__select';
	select.id = id;
	select.name = id;
	div.appendChild(select);

	for (var i = 0 ; i < list.length ; i++) {
		var option = document.createElement('option');
		option.innerHTML = list[i];
		option.value = list[i];
		select.appendChild(option);
		if (i === defaultOffset) {
			option.selected = true;
		}
	}

	select.addEventListener('change', function(evt) {
		onChange(evt.target.value);
	});

	var label = document.createElement('label');
	label.className = 'mdl-selectfield__label';
	label.for = id;
	label.innerHTML = name;
	div.appendChild(label);
}

// function uiSwitch(d) {
// 	// TODO: not yet done
// 	var out = d;
// 	out += '<label class="mdl-switch mdl-js-switch mdl-js-ripple-effect" for="switch-1">';
// 	out += '<input type="checkbox" id="switch-1" class="mdl-switch__input" checked />';
// 	out += '<span class="mdl-switch__label"></span>';
// 	out += '</label>';
// 	return out;
// }

function uiBlock(d) {
	var classes = 'mdl-card__supporting-text mdl-shadow--2dp mdl-color-text--blue-grey-50 mdl-cell';
	var styles = 'display:inline-block;margin:5px;color:black !important;background-color:white !important';
	var out = '';
	for (var i in d.blocks) {
		var D = d.blocks[i];
		out += '<br />' + D.name + ': ';
		out += uiCombo(D.buttons);
	}
	return out;
}

function uiRoundButton(a, b, c) {
	var out = '';
	out += '<button onclick=' + a + ' class="mdl-button mdl-js-button mdl-button--fab mdl-js-ripple-effect" ' + c + '>';
	out += '<i class="material-icons" style="opacity:1">' + b + '</i>';
	out += '</button>';
	return out;
}

/**
 * Handling DataTables with jQuery plugin
 *
 * @param {Array} cols - List of columns, add "+" at beginning to specify a clickable field (seek method)
 * @param {Array} nonum - List of booleans, set true if non-numeric
 * @param {String} id - Id (DOM) of the current table, internal usage for DataTable plugin
 */
function Table(cols, nonum, id, onChange) {
	this.cols = cols;
	this.nonum = nonum;
	this.clickableOffset = new Array(cols.length);
	this.clickableOffset.fill(false);
	this.contentEditable = new Array(cols.length);
	this.contentEditable.fill(false);
	this.onChange = onChange;
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
		} else if (this.cols[c][0] == '~') {
			this.contentEditable[c] = true;
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
			td.innerHTML = cells[i];
		}

		if (this.contentEditable[i]) {
			var _this = this;
			td.initVal = td.innerHTML;
			td.contentEditable = true;
			td.busy = false;

			td.addEventListener('blur', function(evt) {
				if (evt.target.busy) {
					return;
				}
				if (evt.target.initVal == evt.target.innerHTML) {
					return;
				}
				evt.target.busy = true;
				_this.onChange(cells, evt.target.innerHTML);
				evt.target.initVal = evt.target.innerHTML;
				evt.target.busy = false;
			});

			td.addEventListener('keydown', function(evt) {
				if (evt.keyCode != 13 || evt.target.busy) {
					return;
				}
				if (evt.target.initVal == evt.target.innerHTML) {
					return;
				}
				evt.preventDefault();
				evt.target.busy = true;
				_this.onChange(cells, evt.target.innerHTML);
				evt.target.initVal = evt.target.innerHTML;
				evt.target.busy = false;
				evt.target.blur();
			});
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
function uiTableBegin(cols, domId) {
	var out = '';
	var id = domId || '';
	var classes = 'mdl-data-table mdl-js-data-table mdl-data-table--selectable mdl-shadow--2dp';
	out += '<table id="' + id.substr(1) + '" style="margin-left:10px" class="' + classes + '">';
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
		if (!col) {
			continue;
		}
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

	// Flex containers compatibility
	if (typeof this.DOMWrapper.children[1] !== 'undefined') {
		this.DOMWrapper.children[1].style.backgroundColor = 'rgb(32, 32, 32)';
	}
};

/**
 * UI management
 * Container should be currently sized for the purpose
 * lineHeight should be specified in pixels
 */
Hexdump.prototype = new RadareInfiniteBlock();
Hexdump.prototype.constructor = Hexdump;
function Hexdump(containerElement, lineHeight, isBigEndian) {
	this.container = new FlexContainer(containerElement, 'hex');
	this.lineHeight = lineHeight;
	this.bigEndian = isBigEndian;
	this.hexLength = this.Sizes.PAIRS;
	this.init();
	this.resetContainer(containerElement);

	this.showFlags = true;
	this.beingSelected = false;
	this.selectionFirst;
	this.selectionEnd;

	this.lastColorUsed = -1;
	this.bgColors = [
		'rgba(255,0,0,0.4)',
		'rgba(0,255,0,0.4)',
		'rgba(0,92,192,0.4)',
		'rgba(255,255,0,0.4)',
		'rgba(255,0,255,0.4)',
		'rgba(0,255,255,0.4)'
	];

	this.flagColorAssociation = [];
}

/**
 * How many screen we want to retrieve in one round-trip with r2
 */
Hexdump.prototype.infineHeightProvisioning = 2;

/**
 * Size in number of bytes to make a word
 */
Hexdump.prototype.Sizes = {
	PAIRS: -1,
	WORD: 4, // 32 bits
	QUADWORD: 8 // 64 bits
};

/**
 * Define the behavior expected when a value is edited
 */
Hexdump.prototype.setOnChangeCallback = function(callback) {
	this.onChangeCallback = callback;
};

/**
 * Fetch and initialize data
 */
Hexdump.prototype.init = function() {
	var _this = this;

	this.refreshInitialOffset();

	r2.cmdj('ecj', function(colors) {
		_this.colors = colors;
	});

	r2.cmdj('ij', function(info) {
		_this.writable = info.core.iorw;
	});

	for (var key in this.colors) {
		this.colors[key] = 'rgb(' + this.colors[key][0] + ',' + this.colors[key][1] + ',' + this.colors[key][2] + ')';;
	}

	this.selectionMode = !this.writable;

	window.addEventListener('mousedown', function(evt) {
		if (evt.button !== 0) {
			return;
		}
		_this.cleanSelection();
	});

	this.drawContextualMenu();
	this.changeWritable();
};

/**
 * Generic definition of isWritable, if not, we are in select mode
 */
Hexdump.prototype.isWritable = function() {
	return this.writable && !this.selectionMode;
};

/**
 * On change on R/W status on document (!= this.isWritable)
 */
Hexdump.prototype.changeWritable = function() {
	var items = Array.prototype.slice.call(document.getElementsByClassName('writableMenu'));
	var opacity = (this.writable) ? 1.0 : 0.5;

	for (var i = 0 ; i < items.length ; i++) {
		items[i].style.opacity = opacity;
	}
};

/**
 * Called when the frame need to be redrawn
 * Reset the container and draw the previous state
 * TODO: save DOM/Events when quitting widget to reload it faster
 */
Hexdump.prototype.resetContainer = function(container) {
	this.refreshInitialOffset();

	if (typeof this.nav !== 'undefined') {
		this.nav.reset();
	}

	this.container.replug(container);

	// TODO: cache, faster
	this.container.reset();

	this.container.drawBody(function(element) {
		element.appendChild(document.createElement('div')); // offsets
		element.appendChild(document.createElement('div')); // hexpairs
		element.appendChild(document.createElement('div')); // ascii
	});
	this.content = this.container.getBody();
	this.defineInfiniteParams();
};

Hexdump.prototype.getCurrentSelection = function() {
	return this.currentSelection;
};

/**
 * Gather data and set event to configure infinite scrolling
 */
Hexdump.prototype.defineInfiniteParams = function() {
	RadareInfiniteBlock.prototype.defineInfiniteParams.call(this);
	this.nav = new HexPairNavigator(this.howManyLines, this.initialOffset);
	this.nav.updateModifications();
};

/**
 * Sequence to draw the whole UI
 */
Hexdump.prototype.draw = function() {
	var _this = this;
	this.drawControls(this.container.getControls());
	this.drawContent(this.container.getBody(), function() {
		_this.colorizeFlag();
	});
};

/**
 * Colorize a byte depending on 00/7f/ff and ASCII
 */
Hexdump.prototype.colorizeByte = function(elem, val) {
	if (val === '00' || val === 'ff' || val == '7f') {
		elem.style.color = this.colors['b0x' + val];
	} else if (isAsciiVisible(parseInt(val, 16))) {
		elem.style.color = 'rgb(192,192,192)';
	} else {
		elem.style.color = 'inherit';
	}
};

/**
 * Return a color on a cyclic way
 */
Hexdump.prototype.pickColor = function() {
	this.lastColorUsed = (this.lastColorUsed + 1) % this.bgColors.length;
	return this.bgColors[this.lastColorUsed];
};

/**
 * Convert a pair to a word considering endian
 */
Hexdump.prototype.pairs2words = function(list, wordLength) {
	if (wordLength === 1) {
		return list;
	}

	var honoringEndian;
	if (this.bigEndian) {
		honoringEndian = function(x, y) {
			return x + y;
		};
	} else {
		honoringEndian = function(x, y) {
			return y + x;
		};
	}

	var newList = [];
	for (var i = 0 ; i < list.length / 2 ; i++) {
		newList.push(
			honoringEndian(
				list[i * 2],
				list[(i * 2) + 1]
			)
		);
	}

	return this.pairs2words(newList, wordLength / 2);
};

/**
 * Delete selection marks from the UI
 */
Hexdump.prototype.cleanSelection = function(previsualization) {
	if (typeof previsualization === 'undefined') {
		previsualization = false;
	}

	if (!previsualization) {
		this.currentSelection = {};
	}

	var elems;
	do {
		elems = this.listContent.getElementsByClassName('selected');
		for (var i = 0 ; i < elems.length ; i++) {
			elems[i].classList.remove('selected');
		}
	} while (elems.length > 0);
};

/**
 * Draw the selection (emulated)
 * Based on sibling
 */
Hexdump.prototype.processSelection = function(isPrev) {
	if (isPrev) {
		this.cleanSelection(true);
	}

	if (this.selectionFirst === this.selectionEnd) {
		this.selectionFirst.classList.add('selected');
		this.currentSelection = {
			from: this.selectionFirst.offset,
			to: this.selectionFirst.offset
		};
	}

	var start = (this.selectionFirst.offset < this.selectionEnd.offset) ? this.selectionFirst : this.selectionEnd;
	var end = (this.selectionFirst.offset < this.selectionEnd.offset) ? this.selectionEnd : this.selectionFirst;

	this.currentSelection = {
		from: start.offset,
		to: end.offset
	};

	var curNode = start;
	var endFound = false;
	while (!endFound) {
		var sibling = curNode;
		curNode.classList.add('selected');

		while (sibling !== null) {
			if (sibling.offset === end.offset) {
				sibling.classList.add('selected');
				curNode = sibling;
				endFound = true;
				return;
			}

			do {
				curNode = sibling;
				sibling = sibling.nextSibling;
			} while (typeof curNode.offset === 'undefined');
			curNode.classList.add('selected');
		}

		var nextLine = curNode.parentNode.parentNode.nextSibling;
		if (nextLine === null) {
			return;
		}

		while (nextLine.children.length <= 1) {
			if (nextLine === null) {
				return;
			}
			nextLine = nextLine.nextSibling;
		}

		curNode = nextLine.children[1].children[0];
	}
};

/**
 * Populate the content of the contextual menu (on hexpair selection)
 */
Hexdump.prototype.drawContextualMenu = function() {
	var _this = this;

	var exportOp = function(name, range, command, ext) {
		var output;
		r2.cmd(command + ' ' + (range.to - range.from) + ' @' + range.from, function(d) {
			output = d;
		});

		var dialog = _this.createExportDialog('Export as ' + name + ':', output, function() {
			var blob = new Blob([output], {type: 'text/plain'});
			var fileName;
			r2.cmdj('ij', function(d) {
				fileName = basename(d.core.file);
			});
			fileName += '_0x' + range.from.toString(16) + '-0x' + range.to.toString(16) + '.' + ext;
			saveAs(blob, fileName);
		});

		document.body.appendChild(dialog);
		componentHandler.upgradeDom();
		dialog.showModal();
	};

	var exportAs = [
		{ name: 'Assembly', fct: function(evt, range) { return exportOp('ASM', range, 'pca', 'asm'); } },
		{ name: 'Binary', fct: function(evt, range) {
			var bytes = new Uint8Array(_this.nav.getBytes(range));
			var blob = new Blob([bytes], {type: 'application/octet-stream'});
			var fileName;
			r2.cmdj('ij', function(d) {
				fileName = basename(d.core.file);
			});
			fileName += '_0x' + range.from.toString(16) + '-0x' + range.to.toString(16) + '.bin';
			saveAs(blob, fileName);
		} },
		{ name: 'C', fct: function(evt, range) { return exportOp('C', range, 'pc', 'c'); } },
		{ name: 'C half-words (2 bytes)', fct: function(evt, range) { return exportOp('C', range, 'pch', 'c'); } },
		{ name: 'C words (4 bytes)', fct: function(evt, range) { return exportOp('C', range, 'pcw', 'c'); } },
		{ name: 'C dwords (8 bytes)', fct: function(evt, range) { return exportOp('C', range, 'pcd', 'c'); } },
		{ name: 'JavaScript', fct: function(evt, range) { return exportOp('JS', range, 'pcJ', 'js'); } },
		{ name: 'JSON', fct: function(evt, range) { return exportOp('JSON', range, 'pcj', 'json'); } },
		{ name: 'Python', fct: function(evt, range) { return exportOp('Python', range, 'pcp', 'py'); } },
		{ name: 'R2 commands', fct: function(evt, range) { return exportOp('R2 cmd', range, 'pc*', 'r2'); } },
		{ name: 'Shell script', fct: function(evt, range) { return exportOp('Shell script', range, 'pcS', 'txt'); } },
		{ name: 'String', fct: function(evt, range) { return exportOp('string', range, 'pcs', 'txt'); } }
	];
	var applyOp = function(range, operande) {
		var val = prompt('Value (valid hexpair):');
		var op = operande + ' ' + val + ' ' + (range.to - range.from) + ' @' + range.from;
		r2.cmd(op, function() {
			console.log('Call: ' + op);
		});

		_this.nav.updateModifications();

		// Send modifications and reload
		_this.nav.refreshCurrent(function() {
			_this.draw();
		});
	};
	var operations = [
		{ name: 'addition', fct: function(evt, range) { return applyOp(range, 'woa'); } },
		{ name: 'and', fct: function(evt, range) { return applyOp(range, 'woA'); } },
		{ name: 'divide', fct: function(evt, range) { return applyOp(range, 'wod'); } },
		{ name: 'shift left', fct: function(evt, range) { return applyOp(range, 'wol'); } },
		{ name: 'multiply', fct: function(evt, range) { return applyOp(range, 'wom'); } },
		{ name: 'or', fct: function(evt, range) { return applyOp(range, 'woo'); } },
		{ name: 'shift right', fct: function(evt, range) { return applyOp(range, 'wor'); } },
		{ name: 'substraction', fct: function(evt, range) { return applyOp(range, 'wos'); } },
		{ name: 'write looped', fct: function(evt, range) { return applyOp(range, 'wow'); } },
		{ name: 'xor', fct: function(evt, range) { return applyOp(range, 'wox'); } },
		{ name: '2 byte endian swap', fct: function(evt, range) { return applyOp(range, 'wo2'); } },
		{ name: '4 byte endian swap', fct: function(evt, range) { return applyOp(range, 'wo4'); } }
	];

	var items = [
	/*
		TODO
		{
			name: 'Copy length @offset to cmd-line',
			fct: function(evt, range) {
				console.log('Not implemented');
			}
		},
		{
			name: 'Copy bytes to cmd-line',
			fct: function(evt, range) {
				console.log('Not implemented');
			}
		},*/
		{
			name: 'Set flag',
			fct: function(evt, range) {
				var name = prompt('Flag\'s name:');
				r2.cmd('f ' + name + ' ' + (range.to - range.from + 1) + ' @' + range.from, function() {
					_this.nav.refreshCurrent(function() {
						_this.draw();
					});
				});
			}
		},
		{
			name: 'Export as...',
			expand: exportAs,
			requireWritable: false
		},
		{
			name: 'Operations...',
			expand: operations,
			requireWritable: true
		}
	];

	var menu = document.createElement('nav');
	menu.id = 'contextmenuHex';
	menu.classList.add('context-menu');

	var ul = document.createElement('ul');
	menu.appendChild(ul);

	var _this = this;
	var bindAction = function(element, action) {
		element.addEventListener('mousedown', (function(fct) {
			return function(evt) {
				fct(evt, _this.getCurrentSelection());
			};
		}(action)));
	};

	for (var i = 0 ; i < items.length ; i++) {
		var li = document.createElement('li');
		ul.appendChild(li);
		li.appendChild(document.createTextNode(items[i].name));
		li.isSubOpen = false;
		li.requireWritable = items[i].requireWritable;

		if (items[i].requireWritable) {
			li.classList.add('writableMenu');
		}

		li.addEventListener('mouseenter', function(evt) {
			// Cleaning old "active"
			var subactives = Array.prototype.slice.call(evt.target.parentNode.getElementsByClassName('subactive'));
			for (var x = 0 ; x < subactives.length ; x++) {
				subactives[x].classList.remove('subactive');
				subactives[x].isSubOpen = false;
			}
		});

		// expandable menu
		if (typeof items[i].expand !== 'undefined') {
			// Make submenu reachable
			li.addEventListener('mouseenter', function(evt) {
				// If not available on read-only mode
				if (evt.target.requireWritable && !_this.writable) {
					return;
				}

				if (evt.target.isSubOpen) {
					return;
				} else {
					evt.target.isSubOpen = true;
				}

				var subMenu = evt.target.children[0];
				if (typeof subMenu === 'undefined') {
					return;
				}

				var dim = evt.target.getBoundingClientRect();
				var indexOf = Array.prototype.slice.call(evt.target.parentNode.children).indexOf(evt.target);
				evt.target.classList.add('subactive');
				subMenu.style.left = dim.width + 'px';
				subMenu.style.top = indexOf * dim.height + 'px';
			});

			// Creating sub menu
			var subUl = document.createElement('ul');
			li.appendChild(subUl);
			for (var j = 0 ; j < items[i].expand.length ; j++) {
				var subLi = document.createElement('li');
				subUl.appendChild(subLi);
				subLi.appendChild(document.createTextNode(items[i].expand[j].name));
				bindAction(subLi, items[i].expand[j].fct);
			}
		} else {
			bindAction(li, items[i].fct);
		}
	}

	document.body.appendChild(menu);
	componentHandler.upgradeDom();

	var _this = this;
	this.contextMenuOpen = false;
	var closeMenu = function() {
		if (!_this.contextMenuOpen) {
			return;
		}
		menu.classList.remove('active');
		_this.contextMenuOpen = false;
	};

	window.onkeyup = function(e) {
		if (e.keyCode === 27) {
			closeMenu();
		}
	};

	document.addEventListener('click', function() {
		closeMenu();
	});
};

/**
 * Return the export dialog built
 * Don't forget to normalize the output by calling MDL processing
 */
Hexdump.prototype.createExportDialog = function(label, output, save) {
	var dialog = document.createElement('dialog');
	dialog.className = 'mdl-dialog';

	if (!dialog.showModal) {
		dialogPolyfill.registerDialog(dialog);
	}

	/*	CONTENT  */
	var content = document.createElement('div');
	content.className = 'mdl-dialog__content';
	dialog.appendChild(content);

	var desc = document.createTextNode(label);
	content.appendChild(desc);

	var textarea = document.createElement('textarea');
	textarea.style.width = '100%';
	textarea.style.height = '220px';
	content.appendChild(textarea);
	textarea.value = output;

	/*  ACTIONS  */
	var actions = document.createElement('div');
	actions.className = 'mdl-dialog__actions';
	dialog.appendChild(actions);

	var saveButton = document.createElement('button');
	saveButton.className = 'mdl-button';
	saveButton.innerHTML = 'Save';
	saveButton.addEventListener('click', function() {
		dialog.close();
		dialog.parentNode.removeChild(dialog);
		save();
	});
	actions.appendChild(saveButton);

	var closeButton = document.createElement('button');
	closeButton.className = 'mdl-button';
	closeButton.innerHTML = 'Close';
	closeButton.addEventListener('click', function() {
		dialog.close();
		dialog.parentNode.removeChild(dialog);
	});
	actions.appendChild(closeButton);

	return dialog;
};

/**
 * Draw the top-bar controls
 */
Hexdump.prototype.drawControls = function(dom) {
	dom.innerHTML = '';
	var _this = this;

	var controlList = document.createElement('ul');
	controlList.classList.add('controlList');
	dom.appendChild(controlList);

	var wordBlock = document.createElement('li');
	controlList.appendChild(wordBlock);
	var bigEndianBlock = document.createElement('li');
	controlList.appendChild(bigEndianBlock);
	var selectionBlock = document.createElement('li');
	controlList.appendChild(selectionBlock);
	var flagBlock = document.createElement('li');
	controlList.appendChild(flagBlock);

	var selectWord = document.createElement('span');
	selectWord.appendChild(document.createTextNode('Word length: '));
	var select = document.createElement('select');
	selectWord.appendChild(select);

	for (var i in this.Sizes) {
		var option = document.createElement('option');
		option.value = this.Sizes[i];
		option.text = this.Sizes[i] > 0 ? (this.Sizes[i] * 8) + ' bits' : 'pairs';
		if (this.Sizes[i] === this.hexLength) {
			option.selected = true;
		}
		select.appendChild(option);
	}

	select.addEventListener('change', function() {
		_this.hexLength = parseInt(this.value);
		_this.draw();
	}, false);

	// Big endian
	var checkboxBigEndian = document.createElement('input');
	checkboxBigEndian.classList.add('mdl-checkbox__input');
	checkboxBigEndian.type = 'checkbox';
	checkboxBigEndian.checked = this.bigEndian;

	var textBigEndian = document.createElement('span');
	textBigEndian.classList.add('mdl-checkbox__label');
	textBigEndian.appendChild(document.createTextNode('is big endian'));

	var labelCheckboxBE = document.createElement('label');
	labelCheckboxBE.classList.add('mdl-checkbox');
	labelCheckboxBE.classList.add('mdl-js-checkbox');
	labelCheckboxBE.classList.add('mdl-js-ripple-effect');
	labelCheckboxBE.appendChild(checkboxBigEndian);
	labelCheckboxBE.appendChild(textBigEndian);

	checkboxBigEndian.addEventListener('change', function() {
		_this.bigEndian = !_this.bigEndian;
		_this.draw();
	});

	// Selection mode
	var checboxSelection = document.createElement('input');
	checboxSelection.classList.add('mdl-checkbox__input');
	checboxSelection.type = 'checkbox';
	checboxSelection.checked = this.isWritable();

	var textSelection = document.createElement('span');
	textSelection.classList.add('mdl-checkbox__label');
	textSelection.appendChild(document.createTextNode('is editable'));

	var labelCheckboxSelection = document.createElement('label');
	labelCheckboxSelection.classList.add('mdl-checkbox');
	labelCheckboxSelection.classList.add('mdl-js-checkbox');
	labelCheckboxSelection.classList.add('mdl-js-ripple-effect');
	labelCheckboxSelection.appendChild(checboxSelection);
	labelCheckboxSelection.appendChild(textSelection);
	if (!this.writable) {
		checboxSelection.disabled = true;
	}

	checboxSelection.addEventListener('change', function() {
		_this.selectionMode = !_this.selectionMode;
		_this.draw();
	});

	// Big endian
	var checkboxFlags = document.createElement('input');
	checkboxFlags.classList.add('mdl-checkbox__input');
	checkboxFlags.type = 'checkbox';
	checkboxFlags.checked = this.showFlags;

	var textFlags = document.createElement('span');
	textFlags.classList.add('mdl-checkbox__label');
	textFlags.appendChild(document.createTextNode('show flags'));

	var labelFlags = document.createElement('label');
	labelFlags.classList.add('mdl-checkbox');
	labelFlags.classList.add('mdl-js-checkbox');
	labelFlags.classList.add('mdl-js-ripple-effect');
	labelFlags.appendChild(checkboxFlags);
	labelFlags.appendChild(textFlags);

	checkboxFlags.addEventListener('change', function() {
		_this.showFlags = !_this.showFlags;
		_this.draw();
	});

	wordBlock.appendChild(selectWord);
	bigEndianBlock.appendChild(labelCheckboxBE);
	selectionBlock.appendChild(labelCheckboxSelection);
	flagBlock.appendChild(labelFlags);

	// Call MDL
	componentHandler.upgradeDom();
};

/**
 * Returns the color associated with the flag
 */
Hexdump.prototype.getFlagColor = function(flagName) {
	for (var i = 0 ; i < this.flagColorAssociation.length ; i++) {
		if (this.flagColorAssociation[i].name === flagName) {
			return this.flagColorAssociation[i].color;
		}
	}

	var color = this.pickColor();
	this.flagColorAssociation.push({
		name: flagName,
		color: color
	});

	return color;
};

/**
 * Draw the flags from the collection of lines (UI POV) currently displayed
 */
Hexdump.prototype.applyFlags = function(lines, blockInitialOffset, flags) {
	if (!this.showFlags) {
		return;
	}

	for (var i in flags) {
		var line;
		var flag = flags[i];

		// We select the first line concerned by the flag
		for (j = 0 ; j < lines.length ; j++) {
			if (lines[j].offset.start <= flag.offset &&
				lines[j].offset.end >= flag.offset) {
				line = lines[j];
				break;
			}
		}

		// If not found, we pick the next flag
		if (typeof line === 'undefined') {
			continue;
		}

		var flagLine = document.createElement('li');
		flagLine.classList.add('block' + blockInitialOffset);
		flagLine.classList.add('flag');
		flagLine.appendChild(document.createTextNode('[0x' + flag.offset.toString(16) + '] ' + flag.name));
		flagLine.title = flag.size + ' bytes';
		flagLine.style.color = this.getFlagColor(flag.name);
		this.listContent.insertBefore(flagLine, line);
	}
};

/**
 * Returns the index of the line who is containing the offset
 */
Hexdump.prototype.indexOfLine_ = function(offset) {
	var list = [].slice.call(this.listContent.children);
	for (var i = 0 ; i < list.length ; i++) {
		if (typeof list[i].offset !== 'undefined' &&
			list[i].offset.start <= offset &&
			list[i].offset.end >= offset) {
			return i;
		}
	}
	return -1;
};

/**
 * Add colorization on the pairs currently displayed
 * based on the length/color of the flags.
 * Small flags are "painted" at the end to ensure
 * better visibility (not masked by wide flags).
 */
Hexdump.prototype.colorizeFlag = function(reset) {
	if (!this.showFlags) {
		return;
	}

	if (typeof reset === 'undefined') {
		reset = false;
	}

	var list = [].slice.call(this.listContent.children);

	if (reset) {
		for (var i = 0 ; i < list.length ; i++) {
			list[i].backgroundColor = 'none';
		}
	}

	var _this = this;

	// Retrieving all flags with length greater than 2 sorted (small at end)
	this.nav.getFlags(2, function(flags) {
		for (var j = 0 ; j < flags.length ; j++) {
			var end = false;
			var initialLine = _this.indexOfLine_(flags[j].start);
			if (initialLine === -1) {
				console.log('Undefined flag offset');
				return;
			}

			var initialByte = flags[j].start - list[initialLine].offset.start;

			// We walk through lines
			for (var i = initialLine ; i < list.length && !end ; i++) {
				// If it's a "flag line" we move on the next
				if (typeof list[i].offset === 'undefined') {
					continue;
				}

				var hexList = list[i].children[1].children;
				for (var x = initialByte ; x < hexList.length ; x++) {
					// If reach the end, we stop here
					if (hexList[x].offset === flags[j].end) {
						end = true;
						break;
					}
					// We color the byte
					hexList[x].style.backgroundColor = _this.getFlagColor(flags[j].name);
				}

				initialByte = 0;
			}
		}
	});
};

/**
 * Draw 3 chunks on specified DOM node
 */
Hexdump.prototype.drawContent = function(dom, callback) {
	dom.innerHTML = '';

	this.listContent = document.createElement('ul');
	dom.appendChild(this.listContent);

	var _this = this;
	this.listContent.addEventListener('contextmenu', function(evt) {
		if (typeof _this.currentSelection === 'undefined' ||
			typeof _this.currentSelection.from === 'undefined' ||
			typeof _this.currentSelection.to === 'undefined') {
			// If undefined, we chose to have one-byte selection
			_this.currentSelection = {
				from: evt.target.offset,
				to: evt.target.offset
			};
		}
		evt.preventDefault();
		var menu = document.getElementById('contextmenuHex');

		if (_this.contextMenuOpen) {
			menu.classList.remove('active');
		} else {
			menu.classList.add('active');
			menu.style.left = evt.clientX + 'px';
			menu.style.top = evt.clientY + 'px';
		}

		_this.contextMenuOpen = !_this.contextMenuOpen;
	});

	this.nav.get(this.Dir.CURRENT, function(chunk) {
		_this.curChunk = chunk;
	});

	this.nav.get(this.Dir.BEFORE, function(chunk) {
		_this.isTopMax = chunk.offset === 0;
		_this.drawChunk(chunk);
		_this.firstElement = _this.drawChunk(_this.getCurChunk());
	});

	this.nav.get(this.Dir.AFTER, function(chunk) {
		_this.drawChunk(chunk);
		_this.content.scrollTop = 0;
		_this.content.scrollTop = _this.getFirstElement().getBoundingClientRect().top;

		// Everything has been drawn, maybe we should do something more
		if (typeof callback !== 'undefined') {
			callback();
		}
	});
};

/**
 * Draw a chunk before or after the current content
 */
Hexdump.prototype.drawChunk = function(chunk, where) {
	if (chunk.offset === 0 && chunk.hex.length === 0) {
		return this.firstElement;
	}

	var _this = this;
	var drawMethod;
	var size;
	if (this.hexLength === -1) {
		drawMethod = this.drawPairs_;
	} else {
		drawMethod = this.drawWords_;
		size = this.hexLength;
	}

	if (typeof where === 'undefined') {
		where = this.Dir.AFTER;
	}

	var lines = [];
	var firstElement;
	var i;
	for (var x = 0 ; x < chunk.hex.length ; x++) {
		var line = document.createElement('li');
		line.className = 'block' + chunk.offset;

		if (where === this.Dir.AFTER) {
			this.listContent.appendChild(line);
			lines.push(line);
			i = x;
		} else {
			this.listContent.insertBefore(line, this.listContent.firstChild);
			lines.unshift(line);
			i = (chunk.hex.length - 1) - x;
		}

		line.offset = {};
		line.offset.start = chunk.offset + (16 * i);
		line.offset.end = line.offset.start + 15;

		var offset = document.createElement('ul');
		var hexpairs = document.createElement('ul');
		var asciis = document.createElement('ul');

		offset.classList.add('offset');

		var offsetEl = document.createElement('li');
		offset.appendChild(offsetEl);
		offsetEl.appendChild(document.createTextNode('0x' + (chunk.offset + (i * 16)).toString(16)));

		offsetEl.assoc = hexpairs;

		offsetEl.addEventListener('dblclick', function(evt) {
			evt.preventDefault();
			_this.selectionFirst = evt.target.parentNode.nextSibling.children[0];
			_this.selectionEnd = evt.target.parentNode.nextSibling.children[15];
			_this.processSelection();
		});

		hexpairs.style.lineHeight = this.lineHeight + 'px';
		hexpairs.classList.add('hexpairs');

		asciis.classList.add('ascii');

		line.appendChild(offset);
		line.appendChild(hexpairs);
		line.appendChild(asciis);

		drawMethod.apply(
			this,
			[hexpairs, asciis, chunk.hex[i], chunk.ascii[i], chunk.modified, chunk.offset + (16 * i), size]
		);

		if (typeof firstElement === 'undefined') {
			firstElement = line;
		}
	}

	this.applyFlags(lines, chunk.offset, chunk.flags);

	return firstElement;
};

/**
 * Trigerred by scrolling, determine and add content at the right place
 */
Hexdump.prototype.infiniteDrawingContent = function(where, pos, endCallback) {
	var _this = this;
	this.nav.get(where, function(chunk) {
		if (where === _this.Dir.BEFORE) {
			_this.isTopMax = chunk.offset === 0;
		} else {
			if (_this.isTopMax) {
				_this.nav.get(_this.Dir.BEFORE, function(chunk) {
					if (chunk.offset > 0) {
						_this.isTopMax = false;
					}
				});
			}
		}

		if (chunk.offset === 0 && chunk.hex.length === 0) {
			return;
		}

		var removing;
		if (where === _this.Dir.BEFORE) {
			removing = _this.listContent.lastChild.className;
		} else {
			removing = _this.listContent.firstChild.className;
		}
		var elements = Array.prototype.slice.call(document.getElementsByClassName(removing));
		for (var i = 0 ; i < elements.length ; i++) {
			elements[i].parentNode.removeChild(elements[i]);
		}

		_this.drawChunk(chunk, where);
		_this.content.scrollTop = pos;
		_this.colorizeFlag(true);

		endCallback(_this.isTopMax); // pauseScrollEvent = false
	});
};

/**
 * mouse over event to highligh pair-ascii at the same time
 */
Hexdump.prototype.showPairs_ = function(first, second, isOver) {
	if (isOver) {
		first.classList.add('active');
		second.classList.add('active');
	} else {
		first.classList.remove('active');
		second.classList.remove('active');
	}
};

/**
 * Generic method to draw words of any size
 */
Hexdump.prototype.drawWords_ = function(hexpairs, asciis, pairs, chars, modifications, offset, size) {
	var words = this.pairs2words(pairs, size);
	hexpairs.classList.add('words');

	for (var x = 0 ; x < pairs.length ; x++) {
		var asciiEl = document.createElement('li');
		asciiEl.appendChild(document.createTextNode(chars[x]));
		asciis.appendChild(asciiEl);

		this.colorizeByte(asciiEl, pairs[x]);
	}

	for (var x = 0 ; x < words.length ; x++) {
		var hexpairEl = document.createElement('li');
		hexpairEl.appendChild(document.createTextNode('0x' + words[x]));
		hexpairs.appendChild(hexpairEl);
	}
};

/**
 * Default drawing method to draw the pairs with all features
 */
Hexdump.prototype.drawPairs_ = function(hexpairs, asciis, pairs, chars, modifications, offset) {
	hexpairs.classList.add('pairs');
	var _this = this;

	var editableHexEvent = {
		keydown: function(evt) {
			if (evt.keyCode === 13) {
				collectHexpair(evt.target);
			}
		},
		blur: function(evt) {
			collectHexpair(evt.target);
		}
	};

	var editableAsciiEvent = {
		keydown: function(evt) {
			if (evt.keyCode === 13) {
				collectAscii(evt.target);
			}
		},
		blur: function(evt) {
			collectAscii(evt.target);
		}
	};

	var collectHexpair = function(target) {
		if (target.busy) {
			return; // Event has been already triggered elsewhere
		}
		// Don't need to set to false, in each case we remove the node
		target.busy = true;

		// Keep the first 2 valid hex characters
		var regex = target.value.match(/$([a-fA-F0-9]{2})^/);
		if (regex === null) {
			if (typeof target.parentNode === 'undefined') {
				// Solving event conflict
				return;
			}
			alert('Wrong format, expected: [a-fA-F0-9]{2}');
			target.parentNode.innerHTML = target.initValue;
			return;
		}

		var value = regex[0];
		target = target.parentNode;
		var initial = _this.nav.reportChange(target.offset, value);

		target.innerHTML = value;
		target.assoc.innerHTML = hexPairToASCII(value);
		if (initial !== null) {
			target.classList.add('modified');
			target.assoc.classList.add('modified');
			_this.colorizeByte(target, value);
			_this.colorizeByte(target.assoc, value);
			_this.onChangeCallback(target.offset, initial, value);
		}

		target.removeEventListener('keydown', editableHexEvent.keydown);
		target.removeEventListener('blur', editableHexEvent.blur);
	};

	var collectAscii = function(target) {
		var value = target.value[0];
		var hex = ASCIIToHexpair(value);
		target = target.parentNode;
		var initial = _this.nav.reportChange(target.assoc.offset, hex);

		target.innerHTML = value;
		target.assoc.innerHTML = hex;
		if (initial !== null) {
			target.classList.add('modified');
			target.assoc.classList.add('modified');
			_this.colorizeByte(target, value);
			_this.colorizeByte(target.assoc, value);
			_this.onChangeCallback(target.assoc.offset, target.assoc.innerHTML, hex);
		}

		target.removeEventListener('keydown', editableAsciiEvent.keydown);
		target.removeEventListener('blur', editableAsciiEvent.blur);
	};

	for (var x = 0 ; x < pairs.length ; x++) {
		var curOffset = offset + x;

		// If there is a one-byte modification (UI not refresh)
		var checkModification = this.nav.hasNewValue(curOffset);
		// If there is a modification known by r2
		var isModified = this.nav.isModifiedByte(curOffset);
		// If it's a small modification, we update content
		if (checkModification !== null) {
			pairs[x] = checkModification;
			chars[x] = hexPairToASCII(checkModification);
			isModified = true;
		}

		var hexpairEl = document.createElement('li');
		hexpairEl.appendChild(document.createTextNode(pairs[x]));
		hexpairEl.offset = curOffset;
		if (isModified) {
			hexpairEl.classList.add('modified');
		}

		var asciiEl = document.createElement('li');
		asciiEl.appendChild(document.createTextNode(chars[x]));
		if (isModified) {
			asciiEl.classList.add('modified');
		}

		asciiEl.assoc = hexpairEl;
		hexpairEl.assoc = asciiEl;

		hexpairs.appendChild(hexpairEl);
		asciis.appendChild(asciiEl);

		this.colorizeByte(hexpairEl, pairs[x]);
		this.colorizeByte(asciiEl, pairs[x]);

		hexpairEl.addEventListener('mouseenter', function(evt) {
			_this.showPairs_(evt.target, evt.target.assoc, true);
		});

		hexpairEl.addEventListener('mouseleave', function(evt) {
			_this.showPairs_(evt.target, evt.target.assoc, false);
		});

		asciiEl.addEventListener('mouseenter', function(evt) {
			_this.showPairs_(evt.target, evt.target.assoc, true);
		});

		asciiEl.addEventListener('mouseleave', function(evt) {
			_this.showPairs_(evt.target, evt.target.assoc, false);
		});

		if (this.isWritable()) {
			hexpairEl.addEventListener('click', function(evt) {
				if (evt.button !== 0) {
					return;
				}
				evt.preventDefault();
				var form = document.createElement('input');
				form.maxLength = 2;
				form.initValue = evt.target.innerHTML;
				form.value = evt.target.innerHTML;
				form.pattern = '[a-fA-F0-9]{2}';
				evt.target.innerHTML = '';
				evt.target.appendChild(form);
				form.busy = false; // Race-flag
				form.addEventListener('keydown', editableHexEvent.keydown);
				form.addEventListener('blur', editableHexEvent.blur);
				form.focus();
			});

			asciiEl.addEventListener('click', function(evt) {
				if (evt.button !== 0) {
					return;
				}
				evt.preventDefault();
				var form = document.createElement('input');
				form.maxLength = 1;
				form.value = evt.target.innerHTML;
				form.pattern = '(.){1}';
				evt.target.innerHTML = '';
				evt.target.appendChild(form);
				form.addEventListener('keydown', editableAsciiEvent.keydown);
				form.addEventListener('blur', editableAsciiEvent.blur);
				form.focus();
			});
		} else {
			hexpairEl.addEventListener('click', function() {
				_this.beingSelected = false;
				_this.cleanSelection();
			});

			hexpairEl.addEventListener('mousedown', function(evt) {
				if (evt.button !== 0) {
					return;
				}
				evt.preventDefault();
				_this.beingSelected = true;
				_this.selectionFirst = evt.target;
			});

			hexpairEl.addEventListener('mouseover', function(evt) {
				if (!_this.beingSelected) {
					return;
				}
				_this.selectionEnd = evt.target;
				_this.processSelection(true);
			});

			hexpairEl.addEventListener('mouseup', function(evt) {
				if (!_this.beingSelected) {
					return;
				}
				_this.selectionEnd = evt.target;
				_this.processSelection(false);
				_this.beingSelected = false;
			});
		}
	}
};

/**
 * howManyLines = how many lines per chunk
 * Careful at boundaries [0..end]
 */
HexPairNavigator.prototype = new BlockNavigator();
HexPairNavigator.prototype.constructor = HexPairNavigator;
function HexPairNavigator(howManyLines, startOffset) {
	this.howManyBytes = howManyLines * 16;
	this.gap = this.howManyBytes;
	this.currentOffset = startOffset;

	// Define a double-linked list to navigate through chunks
	this.curChunk = undefined;

	this.providerWorker = new Worker('hexchunkProvider.js');
	this.providerWorker.postMessage(this.howManyBytes);

	this.init();
};

/**
 * Telling to r2 that we have a change
 * It's a one-byte modification so we don't reload and keep track
 */
HexPairNavigator.prototype.reportChange = function(offset, value) {
	this.smallModifications.push({
		offset: offset,
		value: value
	});

	r2.cmd('wx ' + value + ' @' + offset, function() {});
};

/**
 * Return if a value has been modified (edit function)
 */
HexPairNavigator.prototype.hasNewValue = function(offset) {
	for (var i = 0 ; i < this.smallModifications.length ; i++) {
		if (this.smallModifications[i].offset === offset) {
			return this.smallModifications[i].value;
		}
	}

	return null;
};

/**
 * Retrieve all modifications from r2
 */
HexPairNavigator.prototype.updateModifications = function() {
	var _this = this;
	this.smallModifications = [];
	this.modifiedBytes = [];
	r2.cmd('wcj', function(d) {
		var d = JSON.parse(d);
		for (var i = 0 ; i < d.length ; i++) {
			var offset = d[i].addr;
			for (var x = 0 ; x < d[i].size ; x++) {
				_this.modifiedBytes.push(offset + x);
			}
		}
	});
};

/**
 * Tell if the byte at the current offset has been modified
 */
HexPairNavigator.prototype.isModifiedByte = function(offset) {
	return (this.modifiedBytes.indexOf(offset) > -1);
};

/**
 * Gets all visibles flags
 */
HexPairNavigator.prototype.getFlags = function(minSize, callback) {
	var filter = function(flags) {
		var filteredFlags = [];
		for (var i = 0 ; i < flags.length ; i++) {
			if (flags[i].size >= minSize) {
				filteredFlags.push({
					name: flags[i].name,
					start: flags[i].offset,
					end: flags[i].offset + flags[i].size
				});
			}
		}

		// We want the biggest first
		filteredFlags.sort(function(a, b) {
			return (a.size > b.size) ? -1 : 1;
		});
		return filteredFlags;
	};

	var flags = [];
	var pings = 0;

	// We don't care about order
	var actuator = function() {
		pings++;
		if (pings < 3) {
			return;
		}
		callback(filter(flags));
	};

	this.get(this.Dir.CURRENT, function(chunk) {
		flags = flags.concat(chunk.flags);
		actuator();
	});
	this.get(this.Dir.BEFORE, function(chunk) {
		flags = flags.concat(chunk.flags);
		actuator();
	});
	this.get(this.Dir.AFTER, function(chunk) {
		flags = flags.concat(chunk.flags);
		actuator();
	});
};

HexPairNavigator.prototype.getBytes = function(range) {
	var bytes;
	r2.cmdj('p8j ' + (range.to - range.from + 1) + ' @' + range.from, function(list) {
		bytes = list;
	});
	return bytes;
};

HexPairNavigator.prototype.refreshChunk = function(which, callback) {
	var modifications = [];
	var _this = this;
	this.get(which, function(chunk) {
		chunk.callback = [];
		modifications = chunk.modified;

		_this.get(which, function(newChunk) {
			newChunk.modified.concat(modifications);
			callback(newChunk);
		}, true);
	});
};

HexPairNavigator.prototype.refreshCurrent = function(callback) {
	var pings = 0;
	// We don't care about order
	var actuator = function() {
		pings++;
		if (pings < 3) {
			return;
		}
		callback();
	};

	this.refreshChunk(this.Dir.CURRENT, function() {
		actuator();
	});
	this.refreshChunk(this.Dir.BEFORE, function() {
		actuator();
	});
	this.refreshChunk(this.Dir.AFTER, function() {
		actuator();
	});
};

function hexPairToASCII(pair) {
	var chr = parseInt(pair, 16);
	if (chr >= 33 && chr <= 126) {
		return String.fromCharCode(chr);
	}

	return '.';
};

function ASCIIToHexpair(ascii) {
	var hex = ascii.charCodeAt(0).toString(16);
	if (hex.length < 2) {
		hex = '0' + hex;
	}

	return hex;
};

function isAsciiVisible(offset) {
	return (offset >= 33 && offset <= 126);
}

function basename(path) {
	return path.split(/[\\/]/).pop();
}

Disasm.prototype = new RadareInfiniteBlock();
Disasm.prototype.constructor = Disasm;
function Disasm(containerElement, lineHeight) {
	this.container = new FlexContainer(containerElement, 'disasm');
	this.lineHeight = lineHeight;
	this.refreshInitialOffset();
	this.init();

	this.offsetHistory = ['0x' + this.initialOffset.toString(16)];
	this.indexOffsetHistory = 0;

	var _this = this;
	seekAction.registerLocalAction('Disassembly', function(offset) {
		var gap = (_this.offsetHistory.length - 1) - _this.indexOffsetHistory;
		for (var i = 0 ; i < gap ; i++) {
			_this.offsetHistory.pop();
		}
		_this.offsetHistory.push(offset);
		_this.indexOffsetHistory = _this.offsetHistory.length - 1;
		_this.nav.refreshCurrentOffset();
		_this.draw();
	});
}

/**
 * How many screen we want to retrieve in one round-trip with r2
 */
Disasm.prototype.infineHeightProvisioning = 3;

/**
 * Fetch and initialize data
 */
Disasm.prototype.init = function() {
	var _this = this;

	this.drawContextualMenu();
	this.drawAnalysisDialog();
	// 5% (default is 20%) : dynamic sized content, re-drawn
	this.defineInfiniteParams(0.05);

	this.container.pause('Crunching some data...');
	this.nav.crunchingData(function() {
		_this.container.resume();
	});
};

Disasm.prototype.resetContainer = function(container) {
	// TODO: cache, faster
	this.container.replug(container);
	this.container.reset();
	this.refreshInitialOffset();
	this.defineInfiniteParams(0.05);
};

/**
 * Gather data and set event to configure infinite scrolling
 */
Disasm.prototype.defineInfiniteParams = function(trigger) {
	RadareInfiniteBlock.prototype.defineInfiniteParams.call(this, trigger);
	this.nav = new DisasmNavigator(this.howManyLines, this.initialOffset);
};

Disasm.prototype.draw = function(callback) {
	var _this = this;
	this.drawControls(this.container.getControls());
	this.container.drawBody(function(element) {
		_this.drawContent(element, function() {
			_this.replaceScrollPosition(_this.nav.currentOffset);
			if (typeof callback !== 'undefined') {
				callback();
			}
		});
	});
};


/**
 * Will trigger analysis from checked analysis method
 * of the analysis dialog (<=> analysisMethod by offset)
 */
Disasm.prototype.processChosenAnalysis = function(endCallback) {
	for (var i = 0 ; i < this.analysisMethods.length ; i++) {
		this.analysisMethods[i].action(this.analysisMethods[i].active);
	}

	/* TODO, adapt to overview panel context
		updateFortune();
		updateInfo();
		updateEntropy();
	*/

	// Reprocessing
	this.nav.crunchingData(function() {
		// After, we refresh the current display
		this.draw(endCallback);
	});
};

Disasm.prototype.drawAnalysisDialog = function() {
	this.analysisMethods = [{
		name: 'Analyze symbols',
		ugly: 'symbols',
		active: false,
		action: function(active) {
			if (!active) {
				return;
			}
			r2.cmd('aa');
		}
	},{
		name: 'Analyse calls',
		ugly: 'calls',
		active: false,
		action: function(active) {
			if (active) {
				r2.cmd('e anal.calls=true;aac');
			} else {
				r2.cmd('e anal.calls=false');
			}
		}
	},{
		name: 'Emulate code',
		ugly: 'code',
		active: false,
		action: function(active) {
			if (active) {
				r2.cmd('e asm.emu=1;aae;e asm.emu=0');
			} else {
				r2.cmd('e asm.emu=false');
			}
		}
	},{
		name: 'Find preludes',
		ugly: 'preludes',
		active: false,
		action: function(active) {
			if (!active) {
				return;
			}
			r2.cmd('aap');
		}
	},{
		name: 'Autoname functions',
		ugly: 'fcts',
		active: false,
		action: function(active) {
			if (!active) {
				return;
			}
			r2.cmd('aan');
		}
	}];

	var _this = this;
	this.analysisDialog = document.createElement('dialog');
	this.analysisDialog.className = 'mdl-dialog';

	if (!this.analysisDialog.showModal) {
		dialogPolyfill.registerDialog(this.analysisDialog);
	}

	var content = document.createElement('div');
	content.className = 'mdl-dialog__content';
	this.analysisDialog.appendChild(content);

	var title = document.createElement('p');
	title.appendChild(document.createTextNode('Pick some analysis method'));
	title.className = 'mdl-typography--text-center';
	content.appendChild(title);

	var methods = document.createElement('ul');
	methods.className = 'mdl-card__supporting-text';
	this.analysisDialog.appendChild(methods);

	for (var i = 0 ; i < this.analysisMethods.length ; i++) {
		var li = document.createElement('li');
		methods.appendChild(li);

		var wrappingLabel = document.createElement('label');
		wrappingLabel.for = this.analysisMethods[i].ugly;
		wrappingLabel.className = 'mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect';
		li.appendChild(wrappingLabel);

		var input = document.createElement('input');
		input.type = 'checkbox';
		input.offset = i;
		input.id = this.analysisMethods[i].ugly;
		input.checked = this.analysisMethods[i].active;
		input.className = 'mdl-checkbox__input';
		wrappingLabel.appendChild(input);

		input.addEventListener('change', function(evt) {
			_this.analysisMethods[evt.target.offset].active = evt.target.checked;
		});

		var name = document.createElement('span');
		name.className = 'mdl-checkbox__label';
		name.appendChild(document.createTextNode(this.analysisMethods[i].name));
		wrappingLabel.appendChild(name);
	}

	var actions = document.createElement('div');
	actions.className = 'mdl-dialog__actions';
	this.analysisDialog.appendChild(actions);

	var closeButton = document.createElement('button');
	closeButton.className = 'mdl-button';
	closeButton.innerHTML = 'Close';
	closeButton.addEventListener('click', function() {
		_this.analysisDialog.close();
	});
	actions.appendChild(closeButton);

	var proceedButton = document.createElement('button');
	proceedButton.className = 'mdl-button';
	proceedButton.innerHTML = 'Proceed';
	proceedButton.addEventListener('click', function() {
		_this.processChosenAnalysis(function() {
			_this.analysisDialog.close();
		});
	});
	actions.appendChild(proceedButton);

	document.body.appendChild(this.analysisDialog);
	componentHandler.upgradeDom();
};

Disasm.prototype.extractOffset_ = function(str) {
	return parseInt(str.slice(5));
};

Disasm.prototype.getCurrentOffset = function() {
	return this.currentOffset;
};

Disasm.prototype.oncontextmenu = function(evt, offset) {
	this.refreshContextMenu(offset);
	var menu = document.getElementById('contextmenuDisasm');
	evt.preventDefault();

	if (this.contextMenuOpen) {
		menu.classList.remove('active');
	} else {
		this.currentOffset = offset;
		menu.classList.add('active');
		menu.style.left = evt.clientX + 'px';
		menu.style.top = evt.clientY + 'px';
	}

	this.contextMenuOpen = !this.contextMenuOpen;
};

Disasm.prototype.onfctmenu = function(evt, fct) {
	evt.preventDefault();

	var offset;
	r2.cmd('?v ' + fct, function(hex) {
		offset = hex;
	});

	var newName = prompt('Rename?', fct);
	if (newName === null || newName === '') {
		return;
	}

	r2.cmd('fr ' + newName + '@ ' + offset);
};

Disasm.prototype.onvarmenu = function(evt, varName) {
	evt.preventDefault();

	var newName = prompt('Rename?', varName);
	if (newName === null || newName === '') {
		return;
	}

	r2.cmd('afvn ' + varName + ' ' + newName);
};

Disasm.prototype.refreshContextMenu = function(offset) {
	// check with aoj first, if 'val' field exists: open
	var isUndefined;
	r2.cmdj('aoj @' + offset, function(info) {
		isUndefined = typeof info[0].val === 'undefined';
	});

	this.drawContextualMenu(!isUndefined);
};

Disasm.prototype.getPresentBlock = function() {
	var blocks = [];
	var bodyChildren = this.container.getBody();
	for (var i = 0 ; i < bodyChildren.length ; i++) {
		blocks.push(this.extractOffset_(bodyChildren[i].className));
	}
	return blocks;
};

Disasm.prototype.drawContent = function(dom, callback) {
	var _this = this;

	var list = this.nav.getShownOffset();
	isTopMax = (list[0] === 0);

	// If we are already at top
	if (this.isTopMax && isTopMax) {
		return;
	} else {
		this.isTopMax = isTopMax;
	}

	// reset container
	this.container.getBody().innerHTML = '';

	for (var i = 0 ; i < list.length ; i++) {
		var domAnchor = document.createElement('span');
		this.container.getBody().appendChild(domAnchor);
		this.nav.get(list[i].offset, list[i].size, function(anchor, last) {
			return function(chunk) {
				_this.drawChunk(chunk, anchor);

				if (last && typeof callback !== 'undefined') {
					callback();
				}
			};
		}(domAnchor, (i === list.length - 1)));
	}
};

/**
 * Draw a chunk before or after the current content
 */
Disasm.prototype.drawChunk = function(chunk, domAnchor) {
	domAnchor.innerHTML = chunk.data;
	var pre = domAnchor.children[0];
	var spans = pre.children;
	var _this = this;
	for (var i = 0 ; i < spans.length; i++) {
		if (spans[i].tagName === 'SPAN') {
			if (spans[i].className.indexOf('offset') !== -1) {
				spans[i].addEventListener('contextmenu', function(id) {
					return function(evt) {
						return _this.oncontextmenu(evt, id);
					};
				}(spans[i].id));
			} else if (spans[i].className.indexOf('fcn') !== -1) {
				spans[i].addEventListener('contextmenu', function(id) {
					return function(evt) {
						return _this.onfctmenu(evt, id);
					};
				}(spans[i].id));
			} else if (spans[i].className.indexOf('var') !== -1) {
				spans[i].addEventListener('contextmenu', function(id) {
					return function(evt) {
						return _this.onvarmenu(evt, id);
					};
				}(spans[i].id));
			}
		}
	}

	// Highligh current offset (seek)
	var curElem = document.getElementById(this.nav.getSeekOffset());
	if (curElem !== null) {
		curElem.classList.add('currentOffset');
	}

	return document.getElementById(domAnchor);
};

Disasm.prototype.infiniteDrawingContent = function(where, pos, endCallback) {
	var _this = this;
	var firstVisibleOffset = this.firstVisibleOffset();
	this.drawContent(this.container.getBody(), function() {
		_this.replaceScrollPosition(firstVisibleOffset);
		endCallback();
	}); // TODO Add stop scroll
};

Disasm.prototype.drawControls = function(dom) {
	var out = uiRoundButton('javascript:disasm.nav.go(-1);disasm.draw();', 'keyboard_arrow_up');
	out += uiRoundButton('javascript:disasm.nav.go(1);disasm.draw();', 'keyboard_arrow_down');
	out += '&nbsp;';
	out += uiButton('javascript:analyze()', 'ANLZ');
	out += uiButton('javascript:comment()', 'CMNT');
	out += uiButton('javascript:info()', 'Info');
	out += uiButton('javascript:rename()', 'RNME');
	out += uiButton('javascript:write()', 'Wrte');

	out += uiButton('javascript:disasm.openAnalysisDialog()', 'Process analysis');
	out += '<ul id="disasm-history"></ul>';

	dom.innerHTML = out;

	this.history = document.getElementById('disasm-history');
	this.drawHistory(this.history);
};

Disasm.prototype.drawHistory = function(dom) {
	var canGoBefore = (this.indexOffsetHistory > 0);
	var canGoAfter = (this.indexOffsetHistory < this.offsetHistory.length - 1);

	var _this = this;
	dom.innerHTML = '';
	for (var i = 0 ; i < this.offsetHistory.length ; i++) {
		var isCurrent = (i === this.indexOffsetHistory);

		var li = document.createElement('li');
		li.className = (isCurrent) ? 'active' : '';
		li.i = i;
		li.x = this.offsetHistory[i];
		li.appendChild(document.createTextNode(this.offsetHistory[i]));
		li.addEventListener('click', function(evt) {
			var x = evt.target.x;
			// Global does not trigger the callback for specific widget
			seekAction.applyGlobal(x.toString());
			_this.indexOffsetHistory = evt.target.i;
			_this.nav.refreshCurrentOffset();
			_this.draw();
		});

		dom.appendChild(li);
	}

	var li = document.createElement('li');
	li.title = 'Seek();';
	li.appendChild(document.createTextNode('?'));
	li.addEventListener('click', function() {
		seek();
	});
	dom.appendChild(li);
};

Disasm.prototype.openAnalysisDialog = function() {
	this.analysisDialog.showModal();
};

/**
 * We want to know the first offset currently visible at the moment
 * when the user ask for more data by scrolling
 */
Disasm.prototype.firstVisibleOffset = function() {
	// Part of the container already scrolled
	var hiddenContainerPart = this.container.getBody().scrollTop;
	if (hiddenContainerPart === 0) {
		return;
	}

	// We want to isolate the chunk that it's visible on the first line visible
	var curSum = 0;
	var elements = this.container.getBody().children;
	var selectedChunk = elements[0];
	for (var i = 1 ; i < elements.length ; i++) {
		var height = elements[i].getBoundingClientRect().height;
		curSum += height;
		// When the current container start in the visible zone
		// we know it's occurs in the previous, we abort here
		if (curSum > hiddenContainerPart) {
			// We restore the previous value, we need it
			curSum -= height;
			break;
		}
		selectedChunk = elements[i];
	}

	// Then, we want to guess approximately which offset was that line
	var visibleSpace = curSum - hiddenContainerPart;
	var hiddenSpace = selectedChunk.getBoundingClientRect().height - visibleSpace;

	var offsetRelatedToThatChunk = this.extractOffset_(selectedChunk.children[0].id);

	var guessedOffset = offsetRelatedToThatChunk + Math.ceil(hiddenSpace / this.lineHeight);

	return guessedOffset;
};

/**
 * We know the last approx. visible offset from firstVisibleOffset
 * we want to adjust the current view to set this same offset on
 * a near position.
 */
Disasm.prototype.replaceScrollPosition = function(offset) {
	//console.log(offset.toString(16));
	if (typeof offset === 'undefined') {
		return;
	}

	// We select the chunk where the offset belongs
	var position = this.nav.getChunkPositionFor(offset);
	if (position === -1) {
		console.log('Chunk position from offset not found');
		return;
	}

	var chunk = this.container.getBody().children[position];
	var blockOffset = this.extractOffset_(chunk.children[0].id);
	var startFromTop = chunk.offsetTop;
	var chunkHeight = chunk.getBoundingClientRect().height;

	var progression = (offset - blockOffset) / this.nav.getSize(blockOffset);
	var adjustment = Math.floor(progression * chunkHeight);
	var requiredScroll = startFromTop + adjustment;

	this.container.getBody().scrollTop = requiredScroll;
};

Disasm.prototype.drawContextualMenu = function(enableAoj) {
	var _this = this;

	var displayRes = function(offset, cmd) {
		var output;
		var fullCmd = cmd + ' @' + offset;
		r2.cmdj(fullCmd, function(d) {
			output = d;
		});

		if (output === null || output.constructor !== Array) {
			alert('No available ouput!');
			return;
		}

		_this.addLongListDialog(output);
	};

	var applyOp = function(offset, cmd, prompting) {
		var arg = '';
		if (typeof prompting !== 'undefined') {
			arg = prompt(prompting + '?');
			if (arg == '') {
				return;
			}
		}

		if (arg != '') {
			cmd += ' ' + arg;
		}

		r2.cmd(cmd + ' @' + offset);
		_this.nav.cleanOldData();
		_this.draw();
	};

	/**
	 * Take a r2 cmd in parameter, will format output into a dialog to validate stuff
	 */
	var presentResults = function(offset, cmd, drawingFct, validationCallback) {
		var output;
		r2.cmd(cmd + ' @' + offset, function(d) {
			output = d;
		});
		drawingFct(this.resultDialog, output, validationCallback);
	};

	var items = [// can add: 'expand' property for expandable menu
		// { name: 'define flag size', shortcut: '$', fct: function(evt, offset) { return applyOp(offset, '$'); } },
		// { name: 'edit bits', shortcut: '1', fct: function(evt, offset) { return applyOp(offset, '1'); } },
		// { name: 'set as byte', shortcut: 'b', fct: function(evt, offset) { return applyOp(offset, 'b'); } },
		// { name: 'set as short word (2 bytes)', shortcut: 'B', fct: function(evt, offset) { return applyOp(offset, 'B'); } },
		// { name: 'set as code', shortcut: 'c', fct: function(evt, offset) { return applyOp(offset, 'c'); } },
		// { name: 'define flag color (fc)', shortcut: 'C', fct: function(evt, offset) { return applyOp(offset, 'C'); } },
		// { name: 'set as data', shortcut: 'd', fct: function(evt, offset) { return applyOp(offset, 'd'); } },
		// { name: 'end of function', shortcut: 'e', fct: function(evt, offset) { return applyOp(offset, 'e'); } },
		{ aoj: true, name: 'analyze function', shortcut: 'f', fct: function(evt, offset) { return applyOp(offset, 'af'); } },
		// { name: 'format', shortcut: 'F', fct: function(evt, offset) { return applyOp(offset, 'F'); } },
		{ aoj: true, name: 'immediate base...', shortcut: 'i', expand: [
			{
				name: 'binary',
				fct: function(evt, offset) { return applyOp(offset, 'ahi b'); }
			},{
				name: 'octal',
				fct: function(evt, offset) { return applyOp(offset, 'ahi o'); }
			},{
				name: 'decimal',
				fct: function(evt, offset) { return applyOp(offset, 'ahi d'); }
			},{
				name: 'hexadecimal',
				fct: function(evt, offset) { return applyOp(offset, 'ahi h'); }
			},{
				name: 'string',
				fct: function(evt, offset) { return applyOp(offset, 'ahi s'); }
			}] },
		// { name: 'merge down (join this and next functions)', shortcut: 'j', fct: function(evt, offset) { return applyOp(offset, 'j'); } },
		// { name: 'merge up (join this and previous function)', shortcut: 'k', fct: function(evt, offset) { return applyOp(offset, 'k'); } },
		// { name: 'highlight word', shortcut: 'h', fct: function(evt, offset) { return applyOp(offset, 'h'); } },
		// { name: 'manpage for current call', shortcut: 'm', fct: function(evt, offset) { return applyOp(offset, 'm'); } },
		{ aoj: true, name: 'rename flag', shortcut: 'n', fct: function(evt, offset) { return applyOp(offset, 'fr', 'Name'); } },
		// { name: 'rename function', shortcut: 'r', fct: function(evt, offset) { return applyOp(offset, 'r'); } },
		// { name: 'find references /r', shortcut: 'R', fct: function(evt, offset) { return applyOp(offset, 'R'); } },
		{ aoj: true, name: 'set string', shortcut: 's', fct: function(evt, offset) { return applyOp(offset, 'Cs'); } },
		// { name: 'set strings in current block', shortcut: 'S', fct: function(evt, offset) { return applyOp(offset, 'S'); } },
		// { name: 'undefine metadata here', shortcut: 'u', fct: function(evt, offset) { return applyOp(offset, 'u'); } },
		{ aoj: false, name: 'find xrefs', shortcut: 'x', fct: function(evt, offset) { return displayRes(offset, 'axtj'); } },
		// { name: 'set as 32bit word', shortcut: 'w', fct: function(evt, offset) { return applyOp(offset, 'w'); } },
		// { name: 'set as 64bit word', shortcut: 'W', fct: function(evt, offset) { return applyOp(offset, 'W'); } }
	];

	var menu = document.getElementById('contextmenuDisasm');
	if (menu === null) {
		var menu = document.createElement('nav');
		menu.id = 'contextmenuDisasm';
		menu.classList.add('context-menu');
	} else {
		menu.innerHTML = '';
	}

	var ul = document.createElement('ul');
	menu.appendChild(ul);

	var _this = this;
	var bindAction = function(element, action) {
		element.addEventListener('mousedown', (function(fct) {
			return function(evt) {
				fct(evt, _this.getCurrentOffset());
			};
		}(action)));
	};

	for (var i = 0 ; i < items.length ; i++) {
		var li = document.createElement('li');
		ul.appendChild(li);
		li.appendChild(document.createTextNode(items[i].name));
		li.isSubOpen = false;

		li.addEventListener('mouseenter', function(evt) {
			// Cleaning old "active"
			var subactives = Array.prototype.slice.call(evt.target.parentNode.getElementsByClassName('subactive'));
			for (var x = 0 ; x < subactives.length ; x++) {
				subactives[x].classList.remove('subactive');
				subactives[x].isSubOpen = false;
			}
		});

		// expandable menu
		if (typeof items[i].expand !== 'undefined' && (enableAoj && items[i].aoj || !items[i].aoj)) {
			// Make submenu reachable
			li.addEventListener('mouseenter', function(evt) {
				if (evt.target.isSubOpen) {
					return;
				} else {
					evt.target.isSubOpen = true;
				}

				var subMenu = evt.target.children[0];
				if (typeof subMenu === 'undefined') {
					return;
				}

				var dim = evt.target.getBoundingClientRect();
				var indexOf = Array.prototype.slice.call(evt.target.parentNode.children).indexOf(evt.target);
				evt.target.classList.add('subactive');
				subMenu.style.left = dim.width + 'px';
				subMenu.style.top = indexOf * dim.height + 'px';
			});

			// Creating sub menu
			var subUl = document.createElement('ul');
			li.appendChild(subUl);
			for (var j = 0 ; j < items[i].expand.length ; j++) {
				var subLi = document.createElement('li');
				subUl.appendChild(subLi);
				subLi.appendChild(document.createTextNode(items[i].expand[j].name));
				bindAction(subLi, items[i].expand[j].fct);
			}
		} else {
			if (enableAoj && items[i].aoj || !items[i].aoj) {
				bindAction(li, items[i].fct);
			} else {
				li.classList.add('disabled');
			}
		}
	}

	document.body.appendChild(menu);
	componentHandler.upgradeDom();

	var _this = this;
	this.contextMenuOpen = false;
	var closeMenu = function() {
		if (!_this.contextMenuOpen) {
			return;
		}
		menu.classList.remove('active');
		_this.contextMenuOpen = false;
	};

	window.onkeyup = function(e) {
		if (e.keyCode === 27) {
			closeMenu();
		}
	};

	document.addEventListener('click', function() {
		closeMenu();
	});
};

/**
 * Show a list of element in a specific dialog
 */
Disasm.prototype.addLongListDialog = function(list) {
	var _this = this;
	var dialog = document.createElement('dialog');
	dialog.className = 'mdl-dialog';

	if (!dialog.showModal) {
		dialogPolyfill.registerDialog(dialog);
	}

	var content = document.createElement('div');
	content.className = 'mdl-dialog__content';
	dialog.appendChild(content);

	var title = document.createElement('p');
	title.appendChild(document.createTextNode('Results'));
	title.className = 'mdl-typography--text-center';
	content.appendChild(title);

	var container = document.createElement('div');
	container.className = 'mdl-card__supporting-text';
	dialog.appendChild(container);

	var table = document.createElement('table');
	table.className = 'disasm-table-dialog';
	table.style.width = '100%';
	table.style.border = '1px dashed red';
	container.appendChild(table);

	var thead = document.createElement('thead');
	table.appendChild(thead);

	var keys = Object.keys(list[0]);
	for (var i = 0 ; i < keys.length ; i++) {
		var th = document.createElement('th');
		th.appendChild(document.createTextNode(keys[i]));
		thead.appendChild(th);
	}

	var tbody = document.createElement('tbody');
	table.appendChild(tbody);

	for (var i = 0 ; i < list.length ; i++) {
		var tr = document.createElement('tr');
		tbody.appendChild(tr);

		for (var j = 0 ; j < keys.length ; j++) {
			var td = document.createElement('td');
			tr.appendChild(td);

			var text;
			if (keys[j] === 'opcode') {
				text = clickableOffsets(list[i][keys[j]]);
			} else if (keys[j] === 'from') {
				var hex = '0x' + list[i][keys[j]].toString(16);
				text = '<a href="javascript:seek(\'' + hex + '\');">0x' + hex + '</a>';
			} else {
				text = list[i][keys[j]];
			}

			td.innerHTML = text;
		}
	}

	var actions = document.createElement('div');
	actions.className = 'mdl-dialog__actions';
	dialog.appendChild(actions);

	var closeButton = document.createElement('button');
	closeButton.className = 'mdl-button';
	closeButton.innerHTML = 'Close';
	closeButton.addEventListener('click', function() {
		dialog.close();
		document.body.removeChild(dialog);
	});
	actions.appendChild(closeButton);

	document.body.appendChild(dialog);
	componentHandler.upgradeDom();

	dialog.showModal();
};

// Should refactor with HexPairNav and go/get methods
/**
 * DisasmNavigator
 * Based on non-fixed size of "chunk"
 * will use:
 *	this.navigationData, as dictionnary [offset => {size, callback, data}]
 *	this.navigationOffsets, for all ordered [offset]
 * 	this.currentlyShown, as currently shown [offset]
 */
DisasmNavigator.prototype = new BlockNavigator();
DisasmNavigator.prototype.constructor = DisasmNavigator;
function DisasmNavigator(howManyLines, startOffset) {
	this.currentOffset = startOffset;
	this.howManyLines = howManyLines;
	this.gap = this.howManyLines * 2;

	this.providerWorker = new Worker('disasmProvider.js');

	this.optimalLines = this.howManyLines * 3;
	this.MINFILL = this.optimalLines * 0.8;

	this.items = [];

	this.init();
}

DisasmNavigator.prototype.init = function() {
	BlockNavigator.prototype.init.apply(this);
	this.currentlyShown = [];
	this.populateFirst();
};

DisasmNavigator.prototype.line2offset = function(line) {
	return line * 2;
};

DisasmNavigator.prototype.offset2line = function(offset) {
	return offset / 2;
};

DisasmNavigator.prototype.configureWorker_ = function() {
	var _this = this;
	this.providerWorker.onmessage = function(e) {
		var item;
		for (var i = 0 ; i < _this.items.length ; i++) {
			if (_this.items[i].offset === e.data.offset &&
				_this.items[i].size === e.data.size) {
				item = _this.items[i];
			}
		}

		if (typeof item === 'undefined') {
			console.log('Unable to find origin item');
			return;
		}

		item.data = e.data.data;
		item.status = _this.Status.COMPLETED;
		for (var i = 0 ; i < item.callback.length ; i++) {
			item.callback[i](item);
		}
		item.callback = [];
	};
};

DisasmNavigator.prototype.cleanOldData = function() {
	for (var i = 0 ; i < this.items.length ; i++) {
		delete this.items[i].data;
		delete this.items[i].status;
	}
};

DisasmNavigator.prototype.crunchingData = function(onReadyCallback) {
	var initWorker = new Worker('disasmNavProvider.js');
	var _this = this;

	initWorker.onmessage = function(e) {
		_this.navigationData = e.data;
		_this.navigationOffsets = Object.keys(e.data);
		_this.navigationOffsets.sort();
		initWorker.terminate();
		onReadyCallback();
	};

	initWorker.postMessage(true);
};

DisasmNavigator.prototype.getOverlappingIntervals = function(start, end) {
	var intervals = [];
	for (var offset in this.navigationData) {
		var startInterval = offset;
		var endInterval = offset + this.navigationData[offset].size;
		if ((startInterval <= start && endInterval >= end) || // all-incl
			(startInterval <= start && endInterval >= start) || // before-overlap
			(startInterval <= end && endInterval >= end) || // after-overlap
			(startInterval >= start && endInterval <= end)) { // included
			intervals.push(offset);
		}
	}
	return intervals;
};

DisasmNavigator.prototype.populateFirst = function() {
	return this.populateFrom(this.currentOffset);
};

/**
 * Create block between [start;end[
 */
DisasmNavigator.prototype.fillGap = function(start, end, artifical) {
	var curSize = end - start;
	// FIX, can't cut everywhere: byte alignment (invalid lines)
	return [{offset: start, size: curSize, artifical: artifical}];
	if (curSize > this.howManyLines) {
		var half = Math.round(end / 2);
		return [{
			offset: start,
			size: Math.round(curSize / 2),
			artifical: artifical
		}].concat(this.fillGap(start + Math.round(curSize / 2), end));
	} else {
		return [{
			offset: start,
			size: curSize,
			artifical: artifical
		}];
	}
};

DisasmNavigator.prototype.populateFrom = function(offset) {
	// From currentOffset
	// I want at least 80% of 3 screens

	// go up of 1 screen, take first in order

	var fromOffset = offset - this.line2offset(this.howManyLines);
	var endOffset = fromOffset + (3 * this.line2offset(this.howManyLines));

	var existingIntervals = this.getOverlappingIntervals(fromOffset, endOffset);

	var requestedIntervals = []; // {offset, size}

	// If they overlap between them, we merge
	for (var i = 0 ; i < existingIntervals.length - 1 ; i++) {
		var endCurrent = existingIntervals[i];
		var startNext = existingIntervals[i + 1];
		if (startNext < endCurrent) {
			if (endNext <= endCurrent) { // inclusive
				requestedIntervals.push({
					offset: existingIntervals[i],
					size: this.navigationData[existingIntervals[i]].size
				});
			} else {
				var endNext = startNext + this.navigationData[startNext].size;
				requestedIntervals.push({
					offset: existingIntervals[i],
					size: endNext - existingIntervals[i]
				});
			}
		}
	}

	if (requestedIntervals.length > 0) {
		// If there is gap before
		if (requestedIntervals[0].offset !== fromOffset) {
			requestedIntervals = requestedIntervals.concat(this.fillGap(fromOffset, requestedIntervals[0].offset));
		}

		// If there is a gap after
		var lastInterval = requestedIntervals[requestedIntervals.length - 1];
		var lastOffsetInterval = (lastInterval.offset + lastInterval.size);
		if (lastOffsetInterval !== endOffset) {
			requestedIntervals = requestedIntervals.concat(this.fillGap(lastOffsetInterval + 1, endOffset));
		}

		// If there is a gap between
		for (var i = 0 ; i < requestedIntervals.length - 1 ; i++) {
			var endCurrent = existingIntervals[i];
			var startNext = existingIntervals[i + 1];

			if (startNext - endCurrent > 1) {
				requestedIntervals = requestedIntervals.concat(this.fillGap(endCurrent + 1, startNext));
			}
		}
	} else {
		requestedIntervals = this.fillGap(fromOffset, endOffset, true);
	}

	this.currentlyShown = requestedIntervals;

	/****
	TODO: check if existing (data field), if not, ask provider
	don't care about total length, but need to find approx. the line requested:
		which interval, starting at? +lineHeight*diff
	*****/
};

/**
 * Returns the current chunks to display
 * Will be conciliated with offset (key)
 */
DisasmNavigator.prototype.getShownOffset = function() {
	return this.currentlyShown;
};

DisasmNavigator.prototype.getSize = function(offset) {
	for (var i = 0 ; i < this.currentlyShown.length ; i++) {
		if (this.currentlyShown[i].offset === offset) {
			return this.currentlyShown[i].size;
		}
	}
	return -1;
};

DisasmNavigator.prototype.getChunkPositionFor = function(offset) {
	for (var i = 0 ; i < this.currentlyShown.length ; i++) {
		if (offset >= this.currentlyShown[i].offset &&
			offset < this.currentlyShown[i].offset + this.currentlyShown[i].size) {
			return i;
		}
	}

	return -1;
};

DisasmNavigator.prototype.get = function(offset, size, callback) {
	// TODO: retrieve data (async) and call
	var item;
	for (var i = 0 ; i < this.items.length ; i++) {
		if (this.items[i].offset === offset &&
			this.items[i].size === size) {
			item = this.items[i];
		}
	}

	if (typeof item === 'undefined') {
		item = {
			offset: offset,
			size: size
		};
		this.items.push(item);
	}

	if (typeof item.data !== 'undefined') {
		return callback(item);
	} else { // Not currently here
		if (typeof item.callback === 'undefined') {
			item.callback = [];
		}
		// Store in callback, could be retrieving or we will start it
		item.callback.push(callback);
		if (item.status !== this.Status.LAUNCHED) { // Need to be retrieved
			item.status = this.Status.LAUNCHED;
			this.providerWorker.postMessage({
				offset: item.offset,
				size: item.size
			});
		}
	}
};

DisasmNavigator.prototype.go = function(dir) {
	this.currentOffset += dir * (this.howManyLines * 2);
	this.populateFrom(this.currentOffset);
};

DisasmNavigator.prototype.refreshCurrentOffset = function() {
	var _this = this;
	r2.cmd('s', function(offset) {
		_this.currentOffset = parseInt(offset, 16);
	});
};

DisasmNavigator.prototype.getSeekOffset = function() {
	return this.currentOffset;
};

/**
 * Define a container in absolute position
 * Create two area: control + body
 */
function FlexContainer(dom, classes) {
	this.classes = (typeof classes === 'undefined') ? '' : classes;
	this.init(dom);
}

FlexContainer.prototype.replug = function(dom) {
	this.container = dom;
	this.container.innerHTML = '';
	this.container.appendChild(this.controls);
	this.container.appendChild(this.body);
};

FlexContainer.prototype.reset = function() {
	this.init(this.container);
};

FlexContainer.prototype.init = function(dom) {
	this.container = dom;
	this.container.innerHTML = '';

	this.controls = document.createElement('div');
	this.body = document.createElement('div');

	this.controls.className = 'flex flex-controls ' + this.classes;
	this.body.className = 'flex flex-body ' + this.classes;

	this.container.appendChild(this.controls);
	this.container.appendChild(this.body);
};

FlexContainer.prototype.getControls = function() {
	return this.controls;
};

FlexContainer.prototype.drawControls = function(callback) {
	this.controls.innerHTML = '';
	callback(this.controls);
};

FlexContainer.prototype.getBody = function() {
	return this.body;
};

FlexContainer.prototype.drawBody = function(callback) {
	this.body.innerHTML = '';
	callback(this.body);
};

FlexContainer.prototype.pause = function(msg) {
	if (!this.dialogHasBeenDrawn) {
		this.drawEmptyDialog();
	}

	this.textDialog.innerHTML = msg;
	this.dialog.showModal();
};

FlexContainer.prototype.drawEmptyDialog = function() {
	var _this = this;
	this.dialog = document.createElement('dialog');
	this.dialog.className = 'mdl-dialog';

	if (!this.dialog.showModal) {
		dialogPolyfill.registerDialog(this.dialog);
	}

	var content = document.createElement('div');
	content.className = 'mdl-dialog__content';
	this.dialog.appendChild(content);

	var icon = document.createElement('p');
	icon.className = 'mdl-typography--text-center';
	content.appendChild(icon);

	var iIcon = document.createElement('i');
	iIcon.className = 'material-icons';
	iIcon.style.fontSize = '54px';
	iIcon.innerHTML = 'error_outline';
	icon.appendChild(iIcon);

	this.textDialog = document.createElement('p');
	content.appendChild(this.textDialog);

	var actions = document.createElement('div');
	actions.className = 'mdl-dialog__actions';
	this.dialog.appendChild(actions);

	var saveButton = document.createElement('button');
	saveButton.className = 'mdl-button';
	saveButton.innerHTML = 'Cancel';
	saveButton.addEventListener('click', function() {
		_this.dialog.close();
	});
	actions.appendChild(saveButton);

	document.body.appendChild(this.dialog);
	componentHandler.upgradeDom();
};

FlexContainer.prototype.resume = function() {
	this.dialog.close();
};

/**
 * domTarget must have a "measurable" height
 * limit, when there is less than {limit}% available to scroll
 * we call the associated event
 */
function InfiniteScrolling(domTarget, howManyScreens, limit) {
	// TOD check properties

	this.domTarget = domTarget;
	this.limit = limit;
	this.howManyScreens = howManyScreens;
	this.screenProportion = 1.0 / this.howManyScreens;
	this.pauseScrollEvent = false;
	this.prevScroll = 0.;

	var _this = this;
	this.domTarget.addEventListener('scroll', function(e) {
		_this.scrollEvent_(e);
	});
}

InfiniteScrolling.prototype.setTopEvent = function(fct) {
	this.ontop = fct;
};

InfiniteScrolling.prototype.setBottomEvent = function(fct) {
	this.onbottom = fct;
};

InfiniteScrolling.prototype.scrollEvent_ = function(e) {
	var _this = this;
	if (this.pauseScrollEvent) {
		return;
	}

	var height = e.target.scrollHeight - e.target.offsetHeight;
	var p = e.target.scrollTop  / height;

	if (!this.isTopMax && p < this.limit && this.prevScroll > p) {
		this.pauseScrollEvent = true;
		var pos = Math.floor(((this.limit + (p - this.limit)) + this.screenProportion) * height);
		this.ontop(pos, function(isTopMax) {
			_this.pauseScrollEvent = false;
		});
	}

	if (p > (1 - this.limit) && this.prevScroll < p) {
		this.pauseScrollEvent = true;
		var pos = Math.floor((((1 - this.limit) + (p - (1 - this.limit))) - this.screenProportion) * height);
		this.onbottom(pos, function(isTopMax) {
			_this.pauseScrollEvent = false;
		});
	}

	this.prevScroll = p;
};

function panelComments() {
	var widget = widgetContainer.getWidget('Comments');
	var c = widgetContainer.getWidgetDOMWrapper(widget);

	updates.registerMethod(widget.getOffset(), panelComments);

	c.style.backgroundColor = '#f0f0f0';
	c.innerHTML = '<br />';
	c.innerHTML += uiButton('javascript:notes()', 'Notes');
	c.innerHTML += '<br /><br />';
	r2.cmd('CC', function(d) {
		var table = new Table(
			['+Offset', '~Comment'],
			[true, false],
			'commentsTable',
			function(row, newVal) {
				var offset = row[0];

				// remove
				r2.cmd('CC- @ ' + offset);

				// add new
				r2.cmd('CCu base64:' + window.btoa(newVal) + ' @ ' + offset);

				update();
			});

		var lines = d.split(/\n/); //clickableOffsets (d).split (/\n/);
		for (var i in lines) {
			var line = lines[i].split(/ (.+)?/);
			if (line.length >= 2) {
				table.addRow([line[0], line[1]]);
			}
		}
		table.insertInto(c);
	});
}

var disasm;

function panelDisasm() {
	var widget = widgetContainer.getWidget('Disassembly');
	var c = widgetContainer.getWidgetDOMWrapper(widget);
	c.classList.add('disasmPanel');

	if (typeof disasm === 'undefined') {
		disasm = new Disasm(c, 24);
	} else {
		disasm.resetContainer(c);
	}

	disasm.draw();
	widget.setDark();

	var recall = function() {
		disasm.refreshInitialOffset();
		disasm.resetContainer(c);
		disasm.draw();
		widget.setDark();
	};

	// Disasm is "seekable", we need to define behavior before and after drawing
	updates.registerMethod(widget.getOffset(), function() {});
	lastViews.registerMethod(widget.getOffset(), recall);
}

var hexdump;

function panelHexdump() {
	var widget = widgetContainer.getWidget('Hexdump');
	var c = widgetContainer.getWidgetDOMWrapper(widget);
	c.classList.add('hexdump');

	if (typeof hexdump === 'undefined') {
		var isBigEndian;
		r2.cmd('e cfg.bigendian', function(b) {
			isBigEndian = (b == 'true');
		});

		hexdump = new Hexdump(c, 24, isBigEndian);
		hexdump.setOnChangeCallback(function(offset, before, after) {
			console.log('changed');
		});
	} else {
		hexdump.resetContainer(c);
	}

	hexdump.draw();
	widget.setDark();

	var recall = function() {
		hexdump.refreshInitialOffset();
		hexdump.resetContainer(c);
		hexdump.draw();
		widget.setDark();
	};

	// Hexdump is "seekable", we need to define behavior before and after drawing
	updates.registerMethod(widget.getOffset(), function() {});
	lastViews.registerMethod(widget.getOffset(), recall);
};

var headersCmd = {
	symbols: {
		cmd: 'isq',
		grep: '!imp',
		ready: false
	},
	imports: {
		cmd: 'isq',
		grep: 'imp.',
		ready: false
	},
	relocs: {
		cmd: 'ir',
		grep: null,
		ready: false
	},
	sections: {
		cmd: 'iSq',
		grep: null,
		ready: false
	},
	strings: {
		cmd: 'izq',
		grep: null,
		ready: false
	},
	sdb: {
		cmd: 'k bin/cur/***',
		grep: null,
		ready: false
	}
};

var infoCellHeight = -1;

function panelOverview() {
	var widget = widgetContainer.getWidget('Overview');
	var c = widgetContainer.getWidgetDOMWrapper(widget);
	lastViews.registerMethod(widget.getOffset(), panelOverview);
	updates.registerMethod(widget.getOffset(), panelOverview);

	var out = '<div class="mdl-grid demo-content">';
	out += '<div class="demo-graphs mdl-shadow--2dp mdl-color--white mdl-cell mdl-cell--8-col" id="info-cell">';
	out += '	<div class="mdl-tabs mdl-js-tabs">';
	out += '		<div class="mdl-tabs__tab-bar" id="overview-tabs">';
	out += '			<a href="#tab-info" class="mdl-tabs__tab is-active">Headers</a>';
	out += '			<a href="#tab-symbols" class="mdl-tabs__tab" onclick="overviewLoad(this, headersCmd.symbols)">Symbols</a>';
	out += '			<a href="#tab-imports" class="mdl-tabs__tab" onclick="overviewLoad(this, headersCmd.imports)">Imports</a>';
	out += '			<a href="#tab-relocs" class="mdl-tabs__tab" onclick="overviewLoad(this, headersCmd.relocs)">Relocs</a>';
	out += '			<a href="#tab-sections" class="mdl-tabs__tab" onclick="overviewLoad(this, headersCmd.sections)">Sections</a>';
	out += '			<a href="#tab-strings" class="mdl-tabs__tab" onclick="overviewLoad(this, headersCmd.strings)">Strings</a>';
	out += '			<a href="#tab-sdb" class="mdl-tabs__tab" onclick="overviewLoad(this, headersCmd.sdb)">SDB</a>';
	out += '		</div>';
	out += '		<div id="overview-content">';
	out += '			<div class="mdl-tabs__panel is-active" id="tab-info"></div>';
	out += '			<div class="mdl-tabs__panel" id="tab-symbols"></div>';
	out += '			<div class="mdl-tabs__panel" id="tab-infos"></div>';
	out += '			<div class="mdl-tabs__panel" id="tab-imports"></div>';
	out += '			<div class="mdl-tabs__panel" id="tab-relocs"></div>';
	out += '			<div class="mdl-tabs__panel" id="tab-sections"></div>';
	out += '			<div class="mdl-tabs__panel" id="tab-strings"></div>';
	out += '			<div class="mdl-tabs__panel" id="tab-sdb"></div>';
	out += '		</div>';
	out += '	</div>';
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
	out += '	<h3>Entropy</h3>';
	out += '	<svg fill="currentColor" viewBox="0 0 500 80" id="entropy-graph"></svg>';
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
	
	componentHandler.upgradeDom();

	// Set max height with MDL behavior
	var infoCellHeight = document.getElementById('info-cell').getBoundingClientRect().height;
	var content = document.getElementById('overview-content');
	content.style.height = infoCellHeight - document.getElementById('overview-tabs').getBoundingClientRect().height + 'px';
	content.style.overflow = 'auto';
}

function updateFortune() {
	r2.cmd('fo', function(d) {
		document.getElementById('fortune').innerHTML = d;
		readFortune();
	});
}

// say a message
function speak(text, callback) {
	if (typeof SpeechSynthesisUtterance === 'undefined') {
		return;
	}
	var u = new SpeechSynthesisUtterance();
	u.text = text;
	u.lang = 'en-US';

	u.onend = function() {
		if (callback) {
			callback();
		}
	};

	u.onerror = function(e) {
		if (callback) {
			callback(e);
		}
	};

	speechSynthesis.speak(u);
}

function readFortune() {
	var f = document.getElementById('fortune').innerHTML;
	speak(f);
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
			if (line.length >= 2) {
				body += '<b>' + line[0] + '</b> ' + line[1] + '<br/>';
			}
		}
		body += '</td><td>';
		for (var i in lines2) {
			var line = lines2[i].split(/ (.+)?/);
			if (line.length >= 2) {
				body += '<b>' + line[0] + '</b> ' + line[1] + '<br/>';
			}
		}
		body += '</td></tr></table>';
		document.getElementById('tab-info').innerHTML = body;
	});
}

function updateEntropy() {
	var eg = document.getElementById('entropy-graph');
	var boxHeight = eg.viewBox.baseVal.height;
	var height = (0 | boxHeight) - 19;
	r2.cmd('p=ej 50 $s @ $M', function(d) {
		var body = '';
		var res = JSON.parse(d);
		var values = new Array();

		for (var i in res.entropy) {
			values.push(res.entropy[i].value);
		}

		var nbvals = values.length;
		var min = Math.min.apply(null, values);
		var max = Math.max.apply(null, values);
		var inc = 500.0 / nbvals;

		// Minimum entropy has 0.1 transparency. Max has 1.
		for (var i in values) {
			var y = 0.1 + (1 - 0.1) * ((values[i] - min) / (max - min));
			var addr = '0x' + res.entropy[i].addr.toString(16);
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
			var addr = '0x' + res.entropy[i].addr.toString(16);
			seek(addr);
		};
	});
}

function overviewLoad(evt, args) {
	if (args.ready) {
		return;
	}

	var cmd = args[0];
	var grep = args[1];

	var cmd = args.cmd;
	if (args.grep) {
		cmd += '~' + args.grep;
	}

	r2.cmd(cmd, function(d) {
		var dest = document.getElementById(evt.href.split('#')[1]);
		dest.innerHTML = '<pre style=\'margin:1.2em;\'>' + clickableOffsets(d) + '<pre>';
	});

	args.ready = true;
}


function getConf(confKey) {
	var local = localStorage.getItem(confKey.name);
	if (local !== null) {
		if (local === 'false') {
			local = false;
		} else if (local === 'true') {
			local = true;
		}
		return local;
	} else {
		return confKey.defVal;
	}
}

function saveConf(confKey, val) {
	localStorage.setItem(confKey.name, val);
	confKey.apply(val);
}

function applyConf(force) {
	force = (typeof force === 'undefined') ? false : force;
	for (var item in R2Conf) {
		var cnf = R2Conf[item];
		if ((!force && getConf(cnf) !== cnf.defVal) || force) {
			cnf.apply(getConf(cnf));
		}
	}
}

function resetConf() {
	for (var item in R2Conf) {
		var cnf = R2Conf[item];
		localStorage.removeItem(cnf.name);
	}
	applyConf(true);
}

var R2Conf = {
	platform: { name: 'platform', defVal: 'x86', apply: function(p) { r2.cmd('e asm.arch=' + p); } },
	bits: { name: 'bits', defVal: '32', apply: function(p) { r2.cmd('e asm.bits=' + p); } },
	os: { name: 'os', defVal: 'Linux', apply: function(p) { console.log('OS is now: ' + p); } }, // missing
	size: { name: 'size', defVal: 'S', apply: function(p) {
			switch (p) {
				case 'S':
					r2.cmd('e asm.bytes=false');
					r2.cmd('e asm.lines=false');
					r2.cmd('e asm.cmtright=false');
					break;
				case 'M':
					r2.cmd('e asm.bytes=false');
					r2.cmd('e asm.lines=true');
					r2.cmd('e asm.lineswidth=8');
					r2.cmd('e asm.cmtright=false');
					break;
				case 'L':
					r2.cmd('e asm.bytes=true');
					r2.cmd('e asm.lines=true');
					r2.cmd('e asm.lineswidth=12');
					r2.cmd('e asm.cmtright=true');
					break;
			};
		}
	},
	decoding: { name: 'decoding', defVal: 'Pseudo', apply: function(p) {
			switch (p) {
				case 'Pseudo':
					r2.cmd('e asm.pseudo=1');
					r2.cmd('e asm.syntax=intel');
					break;
				case 'Opcodes':
					r2.cmd('e asm.pseudo=0');
					r2.cmd('e asm.syntax=intel');
					break;
				case 'ATT':
					r2.cmd('e asm.pseudo=0');
					r2.cmd('e asm.syntax=att');
					break;
			};
		}
	},
	mode: { name: 'mode', defVal: 'PA', apply: function(p) {
			switch (p) {
				case 'PA':
					r2.cmd('e io.va=false');
					break;
				case 'VA':
					r2.cmd('e io.va=true');
					break;
				case 'Debug':
					r2.cmd('e io.va=true');
					r2.cmd('e io.debug=true');
					break;
			};
		}
	},
	analHasNext: { name: 'analHasNext', defVal: true, apply: function(p) { console.log('analHasNext is ' + p); } },
	analSkipNops: { name: 'analSkipNops', defVal: true, apply: function(p) { console.log('analSkipNops is ' + p); } },
	analNonCode: { name: 'analNonCode', defVal: false, apply: function(p) { console.log('analNonCode is ' + p); } },
	colors: { name: 'colors', defVal: true, apply: function(p) { inColor = p; } },
	theme: { name: 'theme', defVal: 'none', apply: function(p) { r2.cmd('eco ' + p); } } // TODO
};

function panelSettings() {
	var widget = widgetContainer.getWidget('Settings');
	var c = widgetContainer.getWidgetDOMWrapper(widget);
	c.innerHTML = '';
	updates.registerMethod(widget.getOffset(), panelSettings);

	var grid = document.createElement('div');
	grid.className = 'mdl-grid';
	c.appendChild(grid);

	var platform = createGrid(grid, 'Platform');
	drawPlatform(platform);

	var disassembly = createGrid(grid, 'Disassembly');
	drawDisassembly(disassembly);

	var coreio = createGrid(grid, 'Core/IO');
	drawCoreIO(coreio);

	var analysis = createGrid(grid, 'Analysis');
	drawAnalysis(analysis);

	var colors = createGrid(grid, 'Colors');
	drawColors(colors);

	var reset = createGrid(grid, 'Reset configuration');
	uiActionButton(reset, function() {
		resetConf();
		update();
	}, 'RESET');

	componentHandler.upgradeDom();
}

function savedFromList(list, name, defaultOffset) {
	var value = defaultOffset;
	var saved = localStorage.getItem(name);
	if (saved !== null) {
		value = list.indexOf(saved);
	}
	return value;
}

function drawPlatform(dom) {
	var archs = ['x86', 'arm', 'mips', 'java', 'dalvik', '6502', '8051', 'h8300', 'hppa', 'i4004', 'i8008', 'lh5801',
		'lm32', 'm68k', 'malbolge', 'mcs96', 'msp430', 'nios2', 'ppc', 'rar', 'sh', 'snes', 'sparc', 'spc700', 'sysz',
		'tms320', 'v810', 'v850', 'ws', 'xcore', 'prospeller', 'gb', 'z80', 'arc', 'avr', 'bf', 'cr16', 'cris', 'csr',
		'dcpu16', 'ebc'];
	uiSelect(dom, 'Platform', archs, archs.indexOf(getConf(R2Conf.platform)), function(item) {
		saveConf(R2Conf.platform, item);
	});

	var bits = ['64', '32', '16', '8'];
	uiSelect(dom, 'Bits', bits, bits.indexOf(getConf(R2Conf.bits)), function(item) {
		saveConf(R2Conf.bits, item);
	});

	var os = ['Linux', 'Windows', 'OSX'];
	uiSelect(dom, 'OS', os, os.indexOf(getConf(R2Conf.os)), function(item) {
		saveConf(R2Conf.os, item);
	});
}

function drawDisassembly(dom) {
	var sizes = ['S', 'M', 'L'];
	uiSelect(dom, 'Size', sizes, sizes.indexOf(getConf(R2Conf.size)), function(item) {
		saveConf(R2Conf.size, item);
	});
	var decoding = ['Pseudo', 'Opcodes', 'ATT'];
	uiSelect(dom, 'Decoding', decoding, decoding.indexOf(getConf(R2Conf.decoding)), function(item) {
		saveConf(R2Conf.decoding, item);
	});
}

function drawCoreIO(dom) {
	var mode = ['PA', 'VA', 'Debug'];
	uiSelect(dom, 'Mode', mode, mode.indexOf(getConf(R2Conf.mode)), function(item) {
		saveConf(R2Conf.mode, item);
	});
}

function drawAnalysis(dom) {
	var configAnal = function(param, state, conf) {
		saveConf(conf, state);
	};

	uiSwitch(dom, 'HasNext', getConf(R2Conf.analHasNext), function(param, state) {
		return configAnal(param, state, R2Conf.analHasNext);
	});
	uiSwitch(dom, 'Skip Nops', getConf(R2Conf.analSkipNops), function(param, state) {
		return configAnal(param, state, R2Conf.analSkipNops);
	});
	uiSwitch(dom, 'NonCode', getConf(R2Conf.analNonCode), function(param, state) {
		return configAnal(param, state, R2Conf.analNonCode);
	});
}

function drawColors(dom) {
	var colors;
	r2.cmdj('ecoj', function(data) {
		colors = data;
	});

	uiSwitch(dom, 'Colors', getConf(R2Conf.colors), function(param, state) {
		saveConf(R2Conf.colors, state);
	});

	// Randomize
	uiActionButton(dom, function() {
		r2.cmd('ecr', function() {
			update();
		});
	}, 'Randomize');

	// Set default
	uiActionButton(dom, function() {
		r2.cmd('ecd', function() {
			update();
		});
	}, 'Reset colors');

	uiSelect(dom, 'Theme', colors, colors.indexOf(getConf(R2Conf.theme)), function(theme) {
		saveConf(R2Conf.theme, theme);
	});
}

function createGrid(dom, name) {
	var div = document.createElement('div');
	div.className = 'mdl-cell mdl-color--white mdl-shadow--2dp mdl-cell--4-col';
	div.style.padding = '10px';
	dom.appendChild(div);

	var title = document.createElement('span');
	title.className = 'mdl-layout-title';
	title.innerHTML = name;
	div.appendChild(title);

	var content = document.createElement('div');
	div.appendChild(content);

	return content;
}
