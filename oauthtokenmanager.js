//
// OAuthTokenManager - looks after APIs needed to get or refresh access tokens
//
const requestp = require('request-promise-native');
const logger = require('./logging.js');
const fido2error = require('./fido2error.js');

// this is only used for a shared admin access token, not for OIDC token responses
// which have to be per-session
var adminTokenResponse = null;

/**
* Obtain a promise for a new access token. The reason that requestp is wrapped in a new promise
* is to allow normalisation of the error to a fido2error.fido2Error.
*/
function getAccessToken(req) {
	return new Promise((resolve, reject) => {
		// if the current access token has more than two minutes to live, use it, otherwise get a new one
		var now = new Date();

		// determine if we are going to work with a per-session tokenResponse from OIDC, or the shared
		// admin access token response
		var isSessionTokenResponse = true;
		var tokenResponse = null;
		if (req != null && req.session != null && req.session.tokenResponse != null) {
			tokenResponse = req.session.tokenResponse;
		}
		// if we haven't found a userTokenResponse, fallback to the admin token response
		if (tokenResponse == null) {
			isSessionTokenResponse = false;
			tokenResponse = adminTokenResponse;
		}

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
					// compute this
					var now = new Date();
					tr.expires_at_ms = now.getTime() + (tr.expires_in * 1000);

					// store the new token response back in either session or global cache
					if (isSessionTokenResponse) {
						req.session.tokenResponse = tr;
					} else {
						adminTokenResponse = tr;
					}


					resolve(tr.access_token);
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
	getAccessToken: getAccessToken
};
