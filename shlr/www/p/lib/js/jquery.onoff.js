/** jquery.onoff - v0.4.0 - 2014-10-30
* https://github.com/timmywil/jquery.onoff
* Copyright (c) 2014 Timmy Willison; Licensed MIT */
(function(global, factory) {
	// AMD
	if (typeof define === 'function' && define.amd) {
		define([ 'jquery' ], factory);
	// CommonJS/Browserify
	} else if (typeof exports === 'object') {
		factory(require('jquery'));
	// Global
	} else {
		factory(global.jQuery);
	}
}(this, function($) {
	'use strict';

	// Common properties to lift for touch or pointer events
	var list = 'over out down up move enter leave cancel'.split(' ');
	var hook = $.extend({}, $.event.mouseHooks);
	var events = {};

	// Support pointer events in IE11+ if available
	if ( window.PointerEvent ) {
		$.each(list, function( i, name ) {
			// Add event name to events property and add fixHook
			$.event.fixHooks[
				(events[name] = 'pointer' + name)
			] = hook;
		});
	} else {
		var mouseProps = hook.props;
		// Add touch properties for the touch hook
		hook.props = mouseProps.concat(['touches', 'changedTouches', 'targetTouches', 'altKey', 'ctrlKey', 'metaKey', 'shiftKey']);

		/**
		 * Support: Android
		 * Android sets pageX/Y to 0 for any touch event
		 * Attach first touch's pageX/pageY and clientX/clientY if not set correctly
		 */
		hook.filter = function( event, originalEvent ) {
			var touch;
			var i = mouseProps.length;
			if ( !originalEvent.pageX && originalEvent.touches && (touch = originalEvent.touches[0]) ) {
				// Copy over all mouse properties
				while(i--) {
					event[mouseProps[i]] = touch[mouseProps[i]];
				}
			}
			return event;
		};

		$.each(list, function( i, name ) {
			// No equivalent touch events for over and out
			if (i < 2) {
				events[ name ] = 'mouse' + name;
			} else {
				var touch = 'touch' +
					(name === 'down' ? 'start' : name === 'up' ? 'end' : name);
				// Add fixHook
				$.event.fixHooks[ touch ] = hook;
				// Add event names to events property
				events[ name ] = touch + ' mouse' + name;
			}
		});
	}

	$.pointertouch = events;

	var count = 1;
	var slice = Array.prototype.slice;

	/**
	 * Create an OnOff object for a given element
	 * @constructor
	 * @param {Element} elem - Element to use pan and zoom
	 * @param {Object} [options] - An object literal containing options
	 *  to override default options (See OnOff.defaults)
	 */
	function OnOff(elem, options) {

		// Allow instantiation without `new` keyword
		if (!(this instanceof OnOff)) {
			return new OnOff(elem, options);
		}

		// Sanity checks
		if (elem.nodeName.toLowerCase() !== 'input' || elem.type !== 'checkbox') {
			return $.error('OnOff should be called on checkboxes');
		}

		// Don't remake
		var d = $.data(elem, OnOff.datakey);
		if (d) {
			return d;
		}

		// Extend default with given object literal
		// Each instance gets its own options
		this.options = options = $.extend({}, OnOff.defaults, options);
		this.elem = elem;
		this.$elem = $(elem).addClass(options.className);
		this.$doc = $(elem.ownerDocument || document);

		// Add guid to event namespace
		options.namespace += $.guid++;

		// Add an ID if none has been added
		if (!elem.id) {
			elem.id = 'onoffswitch' + count++;
		}

		// Enable
		this.enable();

		// Save the instance
		$.data(elem, OnOff.datakey, this);
	}

	OnOff.datakey = '_onoff';

	OnOff.defaults = {
		// The event namespace
		// Should always be non-empty
		// Used to bind jQuery events without collisions
		namespace: '.onoff',

		// The class added to the checkbox (see the CSS file)
		className: 'onoffswitch-checkbox'
	};

	OnOff.prototype = {
		constructor: OnOff,

		/**
		 * @returns {OnOff} Returns the instance
		 */
		instance: function() {
			return this;
		},

		/**
		 * Wrap the checkbox and add the label element
		 */
		wrap: function() {
			var elem = this.elem;
			var $elem = this.$elem;
			var options = this.options;

			// Get or create elem wrapper
			var $con = $elem.parent('.onoffswitch');
			if (!$con.length) {
				$elem.wrap('<div class="onoffswitch"></div>');
				$con = $elem.parent()
					.addClass(elem.className.replace(options.className, ''));
			}
			this.$con = $con;

			// Get or create label
			var $label = $elem.next('label[for="' + elem.id + '"]');
			if (!$label.length) {
				$label = $('<label/>')
					.attr('for', elem.id)
					.insertAfter(elem);
			}
			this.$label = $label.addClass('onoffswitch-label');

			// Inner
			var $inner = $label.find('.onoffswitch-inner');
			if (!$inner.length) {
				$inner = $('<span/>')
					.addClass('onoffswitch-inner')
					.prependTo($label);
			}
			this.$inner = $inner;

			// Switch
			var $switch = $label.find('.onoffswitch-switch');
			if (!$switch.length) {
				$switch = $('<span/>')
					.addClass('onoffswitch-switch')
					.appendTo($label);
			}
			this.$switch = $switch;
		},

		/**
		 * Handles the move event on the switch
		 */
		_handleMove: function(e) {
			if (this.disabled) return;
			this.moved = true;
			this.lastX = e.pageX;
			var right = Math.max(Math.min(this.startX - this.lastX, this.maxRight), 0);
			this.$switch.css('right', right);
			this.$inner.css('marginLeft', -(right / this.maxRight) * 100 + '%');
		},

		/**
		 * Bind the move and end events to the document
		 */
		_startMove: function(e) {
			// Prevent default to avoid touch event collision
			e.preventDefault();
			var moveType, endType;
			if (e.type === 'pointerdown') {
				moveType = 'pointermove';
				endType = 'pointerup';
			} else if (e.type === 'touchstart') {
				moveType = 'touchmove';
				endType = 'touchend';
			} else {
				moveType = 'mousemove';
				endType = 'mouseup';
			}
			var elem = this.elem;
			var $elem = this.$elem;
			var ns = this.options.namespace;
			// Disable transitions
			var $handle = this.$switch;
			var handle = $handle[0];
			var $t = this.$inner.add($handle).css('transition', 'none');

			// Starting values
			this.maxRight = this.$con.width() - $handle.width() -
				$.css(handle, 'margin-left', true) -
				$.css(handle, 'margin-right', true) -
				$.css(handle, 'border-left-width', true) -
				$.css(handle, 'border-right-width', true);
			var startChecked = elem.checked;
			this.moved = false;
			this.startX = e.pageX + (startChecked ? 0 : this.maxRight);

			// Bind document events
			var self = this;
			var $doc = this.$doc
				.on(moveType + ns, $.proxy(this._handleMove, this))
				.on(endType + ns, function() {
					// Reenable transition
					$t.css('transition', '');
					$doc.off(ns);

					setTimeout(function() {
						// If there was a move
						// ensure the proper checked value
						if (self.moved) {
							var checked = self.lastX > (self.startX - self.maxRight / 2);
							if (elem.checked !== checked) {
								elem.checked = checked;
								// Trigger change in case it wasn't already fired
								$elem.trigger('change');
							}
						}
						// Normalize CSS and animate
						self.$switch.css('right', '');
						self.$inner.css('marginLeft', '');
					});
				});
		},

		/**
		 * Binds all necessary events
		 */
		_bind: function() {
			this._unbind();
			this.$switch.on(
				$.pointertouch.down,
				$.proxy(this._startMove, this)
			);
		},

		/**
		 * Enable or re-enable the onoff instance
		 */
		enable: function() {
			// Ensures the correct HTML before binding
			this.wrap();
			this._bind();
			this.disabled = false;
		},

		/**
		 * Unbind all events
		 */
		_unbind: function() {
			this.$doc.add(this.$switch).off(this.options.namespace);
		},

		/**
		 * Disable onoff
		 * Removes all added HTML
		 */
		disable: function() {
			this.disabled = true;
			this._unbind();
		},

		/**
		 * Removes all onoffswitch HTML and leaves the checkbox
		 * Also disables this instance
		 */
		unwrap: function() {
			// Destroys this OnOff
			this.disable();
			this.$label.remove();
			this.$elem.unwrap().removeClass(this.options.className);
		},

		/**
		 * @returns {Boolean} Returns whether the current onoff instance is disabled
		 */
		isDisabled: function() {
			return this.disabled;
		},

		/**
		 * Destroy the onoff instance
		 */
		destroy: function() {
			this.disable();
			$.removeData(this.elem, OnOff.datakey);
		},

		/**
		 * Get/set option on an existing instance
		 * @returns {Array|undefined} If getting, returns an array of
		 *  all values on each instance for a given key. If setting,
		 *  continue chaining by returning undefined.
		 */
		option: function(key, value) {
			var newOpts;
			var options = this.options;
			if (!key) {
				// Avoids returning direct reference
				return $.extend({}, options);
			}

			if (typeof key === 'string') {
				if (arguments.length === 1) {
					return options[ key ] !== undefined ?
						options[ key ] :
						null;
				}
				newOpts = {};
				newOpts[ key ] = value;
			} else {
				newOpts = key;
			}

			// Set options
			$.each(newOpts, $.proxy(function(k, val) {
				switch(k) {
					case 'namespace':
						this._unbind();
						break;
					case 'className':
						this.$elem.removeClass(options.className);
				}
				options[ k ] = val;
				switch(k) {
					case 'namespace':
						this._bind();
						break;
					case 'className':
						this.$elem.addClass(val);
				}
			}, this));
		}
	};

	/**
	 * Extend jQuery
	 * @param {Object|String} options - The name of a method to call
	 *  on the prototype or an object literal of options
	 * @returns {jQuery|Mixed} jQuery instance for regular chaining or
	 *  the return value(s) of a onoff method call
	 */
	$.fn.onoff = function(options) {
		var instance, args, m, ret;

		// Call methods widget-style
		if (typeof options === 'string') {
			ret = [];
			args = slice.call(arguments, 1);
			this.each(function() {
				instance = $.data(this, OnOff.datakey);

				if (!instance) {
					ret.push(undefined);

				// Ignore methods beginning with `_`
				} else if (options.charAt(0) !== '_' &&
					typeof (m = instance[ options ]) === 'function' &&
					// If nothing is returned, do not add to return values
					(m = m.apply(instance, args)) !== undefined) {

					ret.push(m);
				}
			});

			// Return an array of values for the jQuery instances
			// Or the value itself if there is only one
			// Or keep chaining
			return ret.length ?
				(ret.length === 1 ? ret[0] : ret) :
				this;
		}

		return this.each(function() { new OnOff(this, options); });
	};

	return ($.OnOff = OnOff);
}));
