/*
    GNOME Shell integration for Chrome
    Copyright (C) 2016  Yuri Konotopov <ykonotopov@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
 */

GSC.getMessage = function(key) {
	if(GSC && GSC.i18n && GSC.i18n[key])
	{
		var message = GSC.i18n[key];

		for(var i = 1; i < arguments.length; i++)
		{
			message = message.replace('$' + i, arguments[i]);
		}

		return message;
	}

	return key;
};

define('gs-chrome', ['jquery'], function($) {
	"use strict";

	window.SweetTooth = function() {
		var apiObject			= {
			apiVersion:			5,
			shellVersion:			'-1',
			versionValidationEnabled:	true,

			getChromeExtensionId:	function() {
				return GS_CHROME_ID;
			},

			getExtensionErrors:	function(uuid) {
				return sendResolveExtensionMessage("getExtensionErrors", "extensionErrors", {uuid: uuid});
			},

			getExtensionInfo:	function(uuid) {
				return sendResolveExtensionMessage("getExtensionInfo", "extensionInfo", {uuid: uuid});
			},

			installExtension:	function(uuid) {
				return sendResolveExtensionMessage("installExtension", "status", {uuid: uuid});
			},

			launchExtensionPrefs:	function(uuid) {
				sendExtensionMessage("launchExtensionPrefs", null, { uuid: uuid });
			},

			listExtensions:		function() {
				return sendResolveExtensionMessage("listExtensions", "extensions");
			},

			setExtensionEnabled:	function(uuid, enable) {
				return sendResolveExtensionMessage("enableExtension", "success", {uuid: uuid, enable: enable});
			},

			uninstallExtension:	function(uuid) {
				return sendResolveExtensionMessage("uninstallExtension", "success", {uuid: uuid});
			},

			initialize:		function() {
				var ready = $.Deferred();

				if(SweetTooth.shellVersion !== '-1')
				{
					ready.resolve();
				}
				else
				{
					require(['jquery', 'messages'], function($, messages) {
						var connectingInfo = GSC.getMessage('connecting_host_app');
						messages.addInfo(connectingInfo);

						ready.done(function(response) {
							apiObject.shellVersion			= response.shellVersion;
							apiObject.versionValidationEnabled	= response.versionValidationEnabled;

							if(!response.connectorVersion || response.connectorVersion != GS_CHROME_VERSION)
							{
								if(!response.connectorVersion)
									response.connectorVersion = GSC.getMessage('older_connector');
								else
									response.connectorVersion = GSC.getMessage('version', response.connectorVersion);

								messages.addWarning(GSC.getMessage('warning_versions_mismatch', GSC.getMessage('version', GS_CHROME_VERSION), response.connectorVersion));
							}

							$('#message_container')
								.find('.message:contains("' + connectingInfo + '")')
								.remove();
						});

						ready.fail(function(message) {
							messages.addWarning(message ? message : GSC.getMessage('no_host_connector'));
						});

						sendResolveExtensionMessage("initialize", "properties", null, ready);
					});
				}

				return ready;
			}
		};

		window.addEventListener("message", function(event) {
			// We only accept messages from ourselves
			if (event.source != window)
				return;

			if (event.data.type)
			{
				if(event.data.type == "gs-chrome")
				{
					if(event.data.request.signal == 'ExtensionStatusChanged' && apiObject.onchange)
					{
						apiObject.onchange(
							event.data.request.parameters[0],
							event.data.request.parameters[1],
							event.data.request.parameters[2]
						);
					}
					else if(event.data.request.signal == 'org.gnome.Shell' && apiObject.onshellrestart)
					{
						apiObject.onshellrestart();
					}
				}
			}
		}, false);

		function sendResolveExtensionMessage(method, resolveProperty, parameters, deferred)
		{
			function resolveOnSuccess(response, deferred, value)
			{
				if(response && response.success)
				{
					deferred.resolve(value);
				}
				else
				{
					var message = response && response.message ? response.message : GSC.getMessage('error_extension_response');
					deferred.reject(message);
				}
			}

			if(!deferred)
			{
				deferred = $.Deferred();
			}

			sendExtensionMessage(method, function(response) {
					resolveOnSuccess(response, deferred, response[resolveProperty]);
				},
				parameters
			);

			return deferred;
		}

		function sendExtensionMessage(method, callback, parameters)
		{
			var request = { execute: method };
			if(parameters)
				request = $.extend(parameters, request);

			chrome.runtime.sendMessage(
				apiObject.getChromeExtensionId(),
				request,
				callback
			);
		}

		return apiObject;
	} ();
});

gs_chrome_initialized = true;

requirejs.config({
	waitSeconds: 15 // It's fails sometimes with default 7 secs
});
require(['jquery', 'messages', 'gs-chrome'], function($, messages){
	SweetTooth.initialize().always(function() {
		// Start extensions.gnome.org main script
		require(['main'], function(){});
	});
});
