/*
    Gnome-shell integration for Chrome
    Copyright (C) 2015  Yuri Konotopov <ykonotopov@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
 */

/*
 * Hijack require property to disallow execution of main extensions.gnome.org
 * script until extension initializated.
 */
var gs_require_inject = function () {
	gs_chrome_initialized	= false;
	var functionSet		= false;
	var originalRequire	= null;

	Object.defineProperty(window, 'require', {
		get: function () {
			if(functionSet && !gs_chrome_initialized)
				return function() {};

			return originalRequire;
		},
		set: function (fn) {
			if (typeof (fn) === 'function')
				functionSet = true;

			originalRequire = fn;
		}
	});
};

var s = document.createElement('script');

s.type = "text/javascript";
s.textContent = '(' + gs_require_inject + ')()';
(document.head||document.documentElement).appendChild(s);
s.parentNode.removeChild(s);