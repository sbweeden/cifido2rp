//
// OAuthTokenManager - performs client_credentials flow as necessary to get an OAuth token
// and execute a function with that token.
//
const requestp = require('request-promise-native');
const logger = require('./logging.js');
const fido2error = require('./fido2error.js');

var tokenResponse = null;

function setTokenResponse(tr) {
	tokenResponse = tr;
}

/**
* Obtain a promise for a new access token. The reason that requestp is wrapped in a new promise
* is to allow normalisation of the error to a fido2error.fido2Error.
*/
function getAccessToken() {
	return new Promise((resolve, reject) => {
		// if the current access token has more than two minutes to live, use it, otherwise get a new one
		var now = new Date();

		if (tokenResponse != null && tokenResponse.expires_at_ms > (now.getTime() + (2*60*1000))) {
			resolve(tokenResponse.access_token);
		} else {
			var formData = null;
			
			if (tokenResponse != null && tokenResponse.refresh_token != null) {
				formData = {
					"grant_type": "refresh_token",
					"refresh_token": tokenResponse.refresh_token,
					"client_id": process.env.OIDC_CLIENT_ID,
					"client_secret": process.env.OIDC_CLIENT_SECRET
				};
			} else {
				formData = {
					"grant_type": "client_credentials",
					"client_id": process.env.OAUTH_CLIENT_ID,
					"client_secret": process.env.OAUTH_CLIENT_SECRET
				};
			}
			console.log("oauthtokenmanager about to get new token with formData: " + JSON.stringify(formData));

			var options = {
				url: process.env.CI_TENANT_ENDPOINT + "/v1.0/endpoint/default/token",
				method: "POST",
				headers: {
					"Accept": "application/json",
				},
				form: formData,
				json: true
			};

			requestp(options).then((tr) => {
				if (tr && tr.access_token) {
					tokenResponse = tr;
					// compute this
					var now = new Date();
					tokenResponse.expires_at_ms = now.getTime() + (tokenResponse.expires_in * 1000);
					resolve(tokenResponse.access_token);
				} else {
					console.log("oauthtokenmanager requestp(options) unexpected token response: " + (tr != null) ? JSON.stringify(tr) : "null");
					var err = new fido2error.fido2Error("Did not get access token in token response");
					reject(err);
				}
			}).catch((e) => {
				console.log("oauthtokenmanager.getAccessToken inside catch block with e: " + (e != null ? JSON.stringify(e) : "null"));
				var err = null;
				if (e != null && e.error != null && e.error.error_description != null) {
					err = new fido2error.fido2Error(e.error.error_description);
				} else {
					err = new fido2error.fido2Error("Unable to get access_token - check server logs for details");
				}
				reject(err);
			});
		}
	});
}

module.exports = { 
	setTokenResponse: setTokenResponse,
	getAccessToken: getAccessToken
};
