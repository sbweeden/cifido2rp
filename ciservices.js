//
// ciservices - performs user and FIDO2 operations against IBM Cloud Identity
//
const KJUR = require('jsrsasign');
const logger = require('./logging.js');
const tm = require('./oauthtokenmanager.js');
const fido2error = require('./fido2error.js');
const fidoutils = require('./fidoutils.js');
const tokenIntrospection = require('token-introspection')({
	endpoint: process.env.CI_TENANT_ENDPOINT + '/v1.0/endpoint/default/introspect',
	client_id: process.env.OAUTH_CLIENT_ID,
	client_secret: process.env.OAUTH_CLIENT_SECRET
});
const txnprocessing = require('./txnprocessing.js');

//
// Caching logic to reduce number of calls to CI
//

// cache to map rpUuid to rpId
var rpUuidMap = {};
// cache to map rpId to rpUuid
var rpIdMap = {};

function handleErrorResponse(methodName, rsp, e, genericError) {
	// log what we can about this error case
	logger.logWithTS("ciservices." + methodName + " e: " + 
		e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));

	var fidoError = null;

	// if e is already a fido2Error, return it, otherwise try to perform discovery of
	// the error message, otherwise return a generic error message
	if (e != null && e.status == "failed") {
		// seems to already be a fido2Error
		fidoError = e;
	} else if (e != null && e.error != null && e.error.messageId != null && e.error.messageDescription != null) {
		// this looks like one of the typical CI error messages
		fidoError = new fido2error.fido2Error(e.error.messageId + ": " + e.error.messageDescription);

	} else {
		// fallback to the generic error
		fidoError = new fido2error.fido2Error(genericError);
	}

	logger.logWithTS("handleErrorResponse sending error response: " + JSON.stringify(fidoError));	
	rsp.json(fidoError);
}

/**
 * Just calls fetch, but then does some standardized result/error handling for JSON-based API calls
 */
function myfetch(url, fetchOptions) {

	let returnAsJSON = false;
	if (fetchOptions["returnAsJSON"] != null) {
		returnAsJSON = fetchOptions.returnAsJSON;
		delete fetchOptions.returnAsJSON;
	}

	return fetch(
		url,
		fetchOptions
	).then((result) => {
		if (returnAsJSON) {
			if (!result.ok) {
				logger.logWithTS("myfetch unexpected result. status: " + result.status);
				return result.text().then((txt) => {
					throw new fido2error.fido2Error("Unexpected HTTP response code: " + result.status + (txt != null ? (" body: " + txt) : ""));
				});
			} else {
				return result.json();
			}
		} else {
			return result;
		}
	});
}

/**
* Ensure the request contains a "username" attribute, and make sure it's either the
* empty string (if allowed), or is the username of the currently authenticated user. 
*/
function validateSelf(fidoRequest, username, allowEmptyUsername) {

	if (username != null) {
		if (!((fidoRequest.username == username) || (allowEmptyUsername && fidoRequest.username == ""))) {
			throw new fido2error.fido2Error("Invalid username in request");
		}
	} else {
		// no currently authenticated user
		// only permitted if fidoRequest.username is the empty string and allowEmptyUsername
		if (!(fidoRequest.username == "" && allowEmptyUsername)) {
			throw new fido2error.fido2Error("Not authenticated");
		}
	}

	return fidoRequest;
}


/**
* Proxies what is expected to be a valid FIDO2 server request to one of:
* /attestation/options
* /attestation/result
* /assertion/options
* /assertion/result
*
* to the CI server. There is little validation done other than to ensure
* that the client is not sending a request for a user other than the user
* who is currently logged in.
*/
function proxyFIDO2ServerRequest(req, rsp, validateUsername, allowEmptyUsername) {
	var bodyToSend = validateUsername ? validateSelf(req.body, req.session.username, allowEmptyUsername) : req.body;

	// the CI body is slightly different from the FIDO server spec. 
	// instead of username (validity of which has already been checked above), 
	// we need to provide userId which is the CI IUI for the user.
	if (bodyToSend.username != null) {
		delete bodyToSend.username;
		if (req.session.userSCIMId) {
			bodyToSend.userId = req.session.userSCIMId;
		}
	}

	// when performing registrations, I want the registration 
	// enabled immediately so insert this additional option
	if (req.url.endsWith("/attestation/result")) {
		bodyToSend.enabled = true;
	}

	var access_token = null;
	tm.getAccessToken(req)
	.then( (at) => {
		access_token = at;		
		return rpIdTorpUuid(process.env.RPID);
	}).then((rpUuid) => {
		var options = {
			method: "POST",
			headers: {
				"Content-type": "application/json",
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			returnAsJSON: true,
			body: JSON.stringify(bodyToSend)
		};
		logger.logWithTS("proxyFIDO2ServerRequest.options: " + JSON.stringify(options));
		return myfetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + req.url,
			options
		);
	}).then((proxyResponse) => {
		// worked - add server spec status and error message fields
		var rspBody = proxyResponse;
		rspBody.status = "ok";
		rspBody.errorMessage = "";
		logger.logWithTS("proxyFIDO2ServerRequest.success: " + JSON.stringify(rspBody));
		rsp.json(rspBody);
	}).catch((e)  => {
		handleErrorResponse("proxyFIDO2ServerRequest", rsp, e, "Unable to proxy FIDO2 request");
	});
}

/**
* Lookup RP's rpUuid from an rpId
*/
function rpIdTorpUuid(rpId) {
	if (rpIdMap[rpId] != null) {
		return rpIdMap[rpId];
	} else {
		return updateRPMaps()
		.then(() => {
			if (rpIdMap[rpId] != null) {
				return rpIdMap[rpId];
			} else {
				// hmm - no rpId, fatal at this point.
				throw new fido2error.fido2Error("rpId: " + rpId + " could not be resolved");
			}			
		});
	}
}

/**
* Performs an assertion result to the FIDO2 server, and if successful, completes
* the login process.
*/
function validateFIDO2Login(req, rsp) {

	var bodyToSend = req.body;
	
	var access_token = null;
	tm.getAccessToken(req).then((at) => {
		access_token = at;		
		return rpIdTorpUuid(process.env.RPID);
	}).then((rpUuid) => {
		return myfetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/assertion/result",
			{
				method: "POST",
				headers: {
					"Content-type": "application/json",
					"Accept": "application/json",
					"Authorization": "Bearer " + access_token
				},
				body: JSON.stringify(bodyToSend),
				returnAsJSON: true
			}
		);
	}).then((assertionResult) => {
		// FIDO2 login worked
		logger.logWithTS("validateFIDO2Login.assertionResult: " + JSON.stringify(assertionResult));

		// lookup user from id to make sure they are real and still active
		return myfetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/Users?" + new URLSearchParams({ "filter" : 'id eq "' + assertionResult.userId + '"' }),
			{
				method: "GET",
				headers: {
					"Accept": "application/scim+json",
					"Authorization": "Bearer " + access_token
				},
				returnAsJSON: true
			}
		);
	}).then((scimResponse) => {
		if (scimResponse && scimResponse.totalResults == 1) {
			if (scimResponse.Resources[0].active) {
				// ok to login
				req.session.userSCIMId = scimResponse.Resources[0].id;
				req.session.username = scimResponse.Resources[0].userName;
				req.session.userDisplayName = getDisplayNameFromSCIMResponse(scimResponse.Resources[0]);

				return getUserResponse(req);
			} else {
				throw new fido2error.fido2Error("User disabled");	
			}
		} else {
			throw new fido2error.fido2Error("User record not found");
		}
	}).then((userResponse) => {
		rsp.json(userResponse);
	}).catch((e)  => {
		handleErrorResponse("validateFIDO2Login", rsp, e, "Unable to perform FIDO2 login");
	});
}



/**
* First checks that the registration identified by the provided id is owned by the currently 
* logged in user, then Uses a DELETE operation to delete it.
* Returns the remaining registered credentials in the same format as sendUserResponse.
*/
function deleteRegistration(req, rsp) {
	if (req.session.username) {
		var regId = req.body.id;
		if (regId != null) {
			var access_token = null;
			tm.getAccessToken(req).then((at) => {
				access_token = at;
				// first search for the suggested registration
				return myfetch(
					process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + regId,
					{
						method: "GET",
						headers: {
							"Accept": "application/json",
							"Authorization": "Bearer " + access_token
						},
						returnAsJSON: true
					}
				);
			}).then((regToDelete) => {
				// is it owned by the currenty authenticated user
				if (regToDelete.userId == req.session.userSCIMId) {
					return myfetch(
						process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + regId,
						{
							method: "DELETE",
							headers: {
								"Accept": "application/json",
								"Authorization": "Bearer " + access_token
							}
						}
					).then(() => {
						logger.logWithTS("Registration deleted: " + regId);
					});
				} else {
					throw new fido2error.fido2Error("Not owner of registration");
				}
			}).then((deleteResult) => { 
				// we care not about the deleteRequest - just build and send the user response
				sendUserResponse(req, rsp); 
			}).catch((e)  => {
				handleErrorResponse("deleteRegistration", rsp, e, "Unable to delete registration");
			});
		} else {
			rsp.json(new fido2error.fido2Error("Invalid id in request"));
		}
	} else {
		rsp.json(new fido2error.fido2Error("Not logged in"));
	}
}

/**
* Returns the details of the indicated registration, provided it is owned by the currently 
* logged in user.
*/
function registrationDetails(req, rsp) {
	if (req.session.username) {
		var regId = req.query.id;
		if (regId != null) {
			var access_token = null;
			tm.getAccessToken(req).then((at) => {
				access_token = at;
				// first retrieve the suggested registration
				return myfetch(
					process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + regId,
					{
						method: "GET",
						headers: {
							"Accept": "application/json",
							"Authorization": "Bearer " + access_token
						},
						returnAsJSON: true
					}
				);
			}).then((reg) => {
				logger.logWithTS("registrationDetails." + regId + " received: " + JSON.stringify(reg));
				// check it is owned by the currenty authenticated user
				if (reg.userId == req.session.userSCIMId) {
					// if there are any transactions associated with this registration, add them in for display
					let txns = txnprocessing.getTransactionsForCredentialID(reg.attributes.credentialId);
					reg.attributes.transactions = txns;

					rsp.json(reg);
				} else {
					throw new fido2error.fido2Error("Not owner of registration");
				}
			}).catch((e)  => {
				handleErrorResponse("registrationDetails", rsp, e, "Unable to retrieve registration");
			});
		} else {
			rsp.json(new fido2error.fido2Error("Invalid id in request"));
		}
	} else {
		rsp.json(new fido2error.fido2Error("Not logged in"));
	}
}

function getDisplayNameFromSCIMResponse(scimResponse) {
	var result = scimResponse.userName;
	if (scimResponse.name != null && scimResponse.name.formatted != null) {
		result = scimResponse.name.formatted;
	}
	return result;
}

function validateUsernamePassword(req, rsp) {
	var username = req.body.username;
	var password = req.body.password;

	var access_token = null;
	return tm.getAccessToken(req)
	.then((at) => {
		access_token = at;
		return myfetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/Users/authentication",
			{
				method: "POST",
				headers: {
					"Authorization": "Bearer " + access_token,
					"Content-type": "application/scim+json",
					"Accept": "application/scim+json"
				},
				body: JSON.stringify({
					"userName" : username,
					"password": password,
					"schemas": ["urn:ietf:params:scim:schemas:ibm:core:2.0:AuthenticateUser"]
				}),
				returnAsJSON: true
			}
		);
	}).then((authenticationResponse) => {
		// username/password ok

		// get full user profile so that we can check user active and get display name
		return myfetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/Users?" + new URLSearchParams({ "filter" : 'id eq "' + authenticationResponse.id + '"' }),
			{
				method: "GET",
				headers: {
					"Accept": "application/scim+json",
					"Authorization": "Bearer " + access_token
				},
				returnAsJSON: true
			}
		);
	}).then((scimResponse) => {
		//logger.logWithTS("ciservices.validateUsernamePassword got scimResponse: " + JSON.stringify(scimResponse));
		if (scimResponse && scimResponse.totalResults == 1) {
			if (scimResponse.Resources[0].active) {
				// ok to login
				req.session.userSCIMId = scimResponse.Resources[0].id;
				req.session.username = scimResponse.Resources[0].userName;
				req.session.userDisplayName = getDisplayNameFromSCIMResponse(scimResponse.Resources[0]);

				return getUserResponse(req);
			} else {
				throw new fido2error.fido2Error("User disabled");	
			}
		} else {
			throw new fido2error.fido2Error("User record not found");
		}
	}).then((userResponse) => {
		rsp.json(userResponse);
	}).catch((e)  => {
		logger.logWithTS("ciservices.validateUsernamePassword inside catch block with e: " + (e != null ? JSON.stringify(e): "null"));
		rsp.json(e);
	});
}

function updateRPMaps() {
	// reads all relying parties from discovery service updates local caches
	return tm.getAccessToken(null)
	.then((access_token) => {
		return myfetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/discover/fido2",
			{
				method: "GET",
				headers: {
					"Accept": "application/json",
					"Authorization": "Bearer " + access_token
				},
				returnAsJSON: true
			}
		);
	}).then((discoverResponse) => {
		rpUuidMap = [];
		rpIdMap = [];
		// there is a response message schema change happening - tolerate the old and new...
		var rpWrapper = (discoverResponse.fido2 != null ? discoverResponse.fido2 : discoverResponse);
		rpWrapper.relyingParties.forEach((rp) => {
			rpUuidMap[rp.id] = rp.rpId;
			rpIdMap[rp.rpId] = rp.id;
		});
	}).catch((e) => {
		logger.logWithTS("ciservices.updateRPMaps e: " + e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
	});
}

function updateRegistrationsFromMaps(registrationsResponse) {
	registrationsResponse.fido2.forEach((reg) => {
		reg.rpId = (rpUuidMap[reg.references.rpUuid] ? rpUuidMap[reg.references.rpUuid] : "UNKNOWN");
	});
	return registrationsResponse;	
}

function coerceCIRegistrationsToClientFormat(registrationsResponse) {
	return new Promise((resolve, reject) => {
		// Do this check so we only lookup each unknown rpUuid all at once
		var anyUnresolvedRpUuids = false;
		for (var i = 0; i < registrationsResponse.fido2.length && !anyUnresolvedRpUuids; i++) {
			if (rpUuidMap[registrationsResponse.fido2[i].references.rpUuid] == null) {
				anyUnresolvedRpUuids = true;
			}
		}

		// if we need to, refresh the rpUuidMap
		if (anyUnresolvedRpUuids) {
			updateRPMaps()
			.then(() => {
				resolve(updateRegistrationsFromMaps(registrationsResponse));
			});
		} else {
			resolve(updateRegistrationsFromMaps(registrationsResponse));
		}
	});
}

function getUserResponse(req) {

	var username = req.session.username;
	var userId = req.session.userSCIMId;
	var displayName = req.session.userDisplayName;

	var result = { "authenticated": true, "username": username, "displayName": displayName, "credentials": []};

	var search = 'userId="' + userId + '"';
	// to futher filter results for just my rpId, add this
	search += '&attributes/rpId="'+process.env.RPID+'"';

	return tm.getAccessToken(req)
	.then((access_token) => { 
		// This includes an example of how to measure the response time for a call
		var start = (new Date()).getTime();
		return myfetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations?" + new URLSearchParams({ "search" : search}),
			{
				method: "GET",
				headers: {
					"Accept": "application/json",
					"Authorization": "Bearer " + access_token
				},
				returnAsJSON: true	
			}
		).then((r) => {
			var now = (new Date()).getTime();
			console.log("getUserResponse: call to get user registrations took(msec): " + (now-start));
			return r;
		});
	}).then((registrationsResponse) => {
		return coerceCIRegistrationsToClientFormat(registrationsResponse);
	}).then((registrationsResponse) => {
		result.credentials = registrationsResponse.fido2;

		// for each credential add any transactions if present
		if (result.credentials != null) {
			for (let i = 0; i < result.credentials.length; i++) {
				let txns = txnprocessing.getTransactionsForCredentialID(result.credentials[i].attributes.credentialId);
				result.credentials[i].attributes.transactions = txns;		
			}
		}

		return result;
	});
}

/**
* Determines if the user is logged in.
* If so, returns their username and list of currently registered FIDO2 credentials as determined from a CI API. 
* If not returns {"authenticated":false}
*/
function sendUserResponse(req, rsp) {
	if (req.session.username) {

		var access_token = null;
		getUserResponse(req)
		.then((userResponse) => {
			rsp.json(userResponse);
		}).catch((e)  => {
			handleErrorResponse("sendUserResponse", rsp, e, "Unable to get user registrations");
		});
	} else {
		rsp.json({"authenticated": false});
	}
}

/**
* Start of section dedicated to APIs used by the android app
*/

// Debugging utility
function logRequest(api, req) {
	console.log("API: " + api);
	console.log("req keys: " + Object.keys(req));
	console.log("req query: " + (req.query == null ? "" : JSON.stringify(req.query)));
	console.log("req params: " + (req.params == null ? "" : JSON.stringify(req.params)));
	console.log("req body: " + (req.body == null ? "" : JSON.stringify(req.body)));
	console.log("req cookies: " + (req.cookies == null ? "" : JSON.stringify(req.cookies)));
}

/**
* Promise-based function to return username and credentials response
*/
function getUsernameAndCredentialsResponse(req, username, requireSignedInCookie) {
	var result = {};

	// For this simple app, username is determined if two cookies exist
	// signed-in=yes
	// username=<value>
	
	// in a real app that should be replaced with oauth access tokens....
	if (username == null) {
		username = req.cookies["username"]; 
	}
	
	if (username != null && (!requireSignedInCookie || req.cookies["signed-in"] == "yes")) {
		result["username"] = req.cookies["username"];

		var access_token = null;
		var rpUuid = null;
		var userId = null;
		return tm.getAccessToken(req)
			.then((at) => {
				access_token = at;
				return rpIdTorpUuid(process.env.RPID);
			}).then((ruu) => {
				rpUuid = ruu;

				// now resolve username to userId
				return myfetch(
					process.env.CI_TENANT_ENDPOINT + "/v2.0/Users?" + new URLSearchParams({ "filter" : 'userName eq "' + username + '"' }),
					{
						method: "GET",
						headers: {
							"Accept": "application/scim+json",
							"Authorization": "Bearer " + access_token
						},
						returnAsJSON: true
					}
				);
			}).then((scimResponse) => {
				if (scimResponse && scimResponse.totalResults == 1) {
					if (scimResponse.Resources[0].active) {
						// ok to proceed
						userId = scimResponse.Resources[0].id;

						result["id"] = userId;

						//
						// Search based on userId and filter on the rpUuid as well
						//						
						var search = 'userId="' + userId + '"';
						search += '&references/rpUuid="'+rpUuid+'"';

						var url = process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations?" + new URLSearchParams({ "search" : search});
						var options = {
							method: "GET",
							headers: {
								"Accept": "application/json",
								"Authorization": "Bearer " + access_token
							},
							returnAsJSON: true
						};

						var start = (new Date()).getTime();
						return myfetch(
							url,
							options
						).then((r) => {
							var now = (new Date()).getTime();
							console.log("getUsernameAndCredentialsResponse: call to get user registrations with options: " + JSON.stringify(options) + " took(msec): " + (now-start));
							return r;
						});
					} else {
						throw "user not active";
					}
				} else {
					throw "user not found";
				}
			}).then((registrationsResponse) => {
				// populate result credentials - filter to only include those for our rpID
				result["credentials"] = [];
				registrationsResponse.fido2.forEach((reg) => {
					if (reg.attributes.rpId == process.env.RPID) {
						// determine aaguidStr and publicKeyPEM
						var aaguidStr = reg.attributes.aaGuid;
						if (aaguidStr == null) {
							aaguidStr = "00000000-0000-0000-0000-000000000000";
						}
						var coseKey = fidoutils.publicKeyStringToCOSEKey(reg.attributes.credentialPublicKey);
						var pk = fidoutils.coseKeyToPublicKey(coseKey);
						var publicKeyPEM = fidoutils.publicKeyToPEM(pk);

						result.credentials.push({
							"credId": reg.attributes.credentialId,
							"aaguid": KJUR.hextob64u(aaguidStr.replace(/-/g,"")),
							"publicKey": publicKeyPEM,
							"prevCounter": (reg.attributes.counter != null ? reg.attributes.counter : 0)
						});
					}
				});

				// done
				return result;
			}).catch((e) => {
				console.log("getUsernameAndCredentialsResponse exception: " + e);
				result = {};
				return result;
			});
	} else {
		debugLog("getUsernameAndCredentialsResponse: It doesn't appear there is any user signed in!");
	}
	
	return result;
}

function androidAssetLinks(req, rsp) {
	rsp.json(
		[
		  {
		    "relation": [
		      "delegate_permission/common.handle_all_urls",
		      "delegate_permission/common.get_login_creds"
		    ],
		    "target": {
		      "namespace": "web",
		      "site": "https://" + process.env.RPID
		    }
		  },
		  {
		    "relation": [
		      "delegate_permission/common.handle_all_urls",
		      "delegate_permission/common.get_login_creds"
		    ],
		    "target": {
		      "namespace": "android_app",
		      "package_name": "com.example.android.fido2",
		      "sha256_cert_fingerprints": [
		        process.env.ANDROID_CERT_FINGERPRINT
		      ]
		    }
		  }
		]
	);	
}

function sendAndroidResponse(rsp, result) {
	//console.log("sendAndroidResponse: called with result: " + JSON.stringify(result));
	if (result.cookies) {
		result.cookies.forEach((c) => {
			//rsp.set('set-cookie', c);
			rsp.cookie(c.name, c.value, c.options);
		});
	}
	if (result.status != "ok") {
		rsp.status(400);
	}
	rsp.json(result.body);
}

function androidUsername(req, rsp) {
	//logRequest("androidUsername", req);

	var result = {
		"status": "ok",
		"body": {},
		"cookies": []
	};

	var username = req.body.username;
	if (username != null) {
		getUsernameAndCredentialsResponse(req, username, false)
		.then((ucr) => {
			result.body = ucr;
			result.cookies.push({"name": "username", "value": username, "options":  { "path": "/"}});
			sendAndroidResponse(rsp, result);
		}).catch((e) => {
			result.status = "failed";
			result.body = {"error": "androidUsername unexpected error"};
			sendAndroidResponse(rsp, result);
		});
		
	} else {
		result.status = "failed";
		result.body = { "error": "no username supplied" };
		sendAndroidResponse(rsp, result);
	}
}

function androidPassword(req, rsp) {
	logRequest("androidPassword", req);
	var result = {
		"status": "ok",
		"body": {},
		"cookies": []
	};

	var username = req.cookies["username"];
	var password = req.body.password;
	if (username != null && password != null) {
		// validate username and password against CI
		tm.getAccessToken(req)
		.then((access_token) => {
			return myfetch(
				process.env.CI_TENANT_ENDPOINT + "/v2.0/Users/authentication",
				{
					method: "POST",
					headers: {
						"Authorization": "Bearer " + access_token,
						"Content-type": "application/scim+json",
						"Accept": "application/scim+json"
					},
					body: JSON.stringify({
						"userName" : username,
						"password": password,
						"schemas": ["urn:ietf:params:scim:schemas:ibm:core:2.0:AuthenticateUser"]
					}),
					returnAsJSON: true
				}
			);
		}).then((scimResponse) => {
			// logged in ok
			return getUsernameAndCredentialsResponse(req, username, false);
		}).then((ucr) => {
			result.body = ucr;
			result.cookies.push({"name": "signed-in", "value": "yes", "options": {"path": "/"}});
			sendAndroidResponse(rsp, result);
		}).catch((e)  => {
			console.log(e);
			result.status = "failed";
			result.body = {"error": "androidPassword authentication failed"};
			sendAndroidResponse(rsp, result);
		});
	} else {
		result.status = "failed";
		result.body = { "error": "no username and password available" };
		sendAndroidResponse(rsp, result);
	}
}

function androidGetKeys(req, rsp) {
	logRequest("androidGetKeys", req);
	var result = {
			"status": "ok",
			"body": {
			},
			"cookies" : [
			]
		};
	
	getUsernameAndCredentialsResponse(req, null, false)
	.then((ucr) => {
		result.body = ucr;
		sendAndroidResponse(rsp, result);
	}).catch((e) => {
		console.log(e);
		result.status = "failed";
		result.body = {"error": "androidGetKeys unexpected error"};
		sendAndroidResponse(rsp, result);
	});
}

function androidRegisterRequest(req, rsp) {
	logRequest("androidRegisterRequest", req);
	var result = {
		"status": "ok",
		"body": {
		},
		"cookies" : [
		]
	};

	var username = req.cookies["username"];
	if (username != null) {
		tm.getAccessToken(req)
		.then((at) => {
			access_token = at;
			return rpIdTorpUuid(process.env.RPID);
		}).then((ruu) => {
			rpUuid = ruu;

			// now resolve username to check it's legit, and get display name
			return myfetch(
				process.env.CI_TENANT_ENDPOINT + "/v2.0/Users?" + new URLSearchParams({ "filter" : 'userName eq "' + username + '"' }),
				{
					method: "GET",
					headers: {
						"Accept": "application/scim+json",
						"Authorization": "Bearer " + access_token
					},
					returnAsJSON: true
				}
			);
		}).then((scimResponse) => {
			if (scimResponse && scimResponse.totalResults == 1) {
				if (scimResponse.Resources[0].active) {
					// ok to proceed
					var user = scimResponse.Resources[0];

					var displayName = username;
					if (user.name != null && user.name.formatted != null && user.name.formatted.length > 0) {
						displayName = user.name.formatted;
					}

					// prepare attestation options body for CI
					var reqBody = {
						"userId": user.id,
						"displayName": displayName
					};
					if (req.body.attestation != null) {
						reqBody["attestation"] = req.body.attestation;
					}

					if (req.body.authenticatorSelection != null) {
						reqBody["authenticatorSelection"] = req.body.authenticatorSelection;
					}

					// call CI
					return myfetch(
						process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/attestation/options",
						{
							method: "POST",
							headers: {
								"Content-type": "application/json",
								"Accept": "application/json",
								"Authorization": "Bearer " + access_token
							},
							body: JSON.stringify(reqBody),
							returnAsJSON: true
						}
					);
				} else {
					throw "user not active";
				}
			} else {
				throw "user not found";
			}
		}).then((rspBody) => {
			// remove these - the android app doesn't understand them
			delete rspBody["status"];
			delete rspBody["errorMessage"];
			delete rspBody["extensions"];

			// also the androidapp only understands one algorithm, and if you pass it others, it fails
			rspBody.pubKeyCredParams = [ { "alg": -7, "type": "public-key" } ];

			result.body = rspBody;
			sendAndroidResponse(rsp, result);
		}).catch((e) => {
			console.log(e);
			result.status = "failed";
			result.body = {"error": "androidRegisterRequest unexpected error"};
			sendAndroidResponse(rsp, result);
		});
	} else {
		result.status = "failed";
		result.body = { "error": "no username supplied" };
		sendAndroidResponse(rsp, result);
	}
}

function androidRegisterResponse(req, rsp) {
	logRequest("androidRegisterResponse", req);
	var result = {
		"status": "ok",
		"body": {
		},
		"cookies" : [
		]
	};

	// we require these to be present
	var id = req.body.id;
	var rawId = req.body.rawId;
	var type = req.body.type;
	var response = req.body.response;
	var getClientExtensionResults = {};
	if (req.body.getClientExtensionResults != null) {
		getClientExtensionResults = req.body.getClientExtensionResults
	}

	if (id != null && rawId != null && type != null && response != null) {
		// if friendlyName is provided, use it, otherwise call it "android-<datestr>"
		var nickname = req.body.nickname;
		if (nickname == null) {
			nickname = "androidapp-" + (new Date()).toISOString();
		}

		// validate the registration via the FIDO2 server
		tm.getAccessToken(req)
		.then((at) => {
			access_token = at;
			return rpIdTorpUuid(process.env.RPID);
		}).then((ruu) => {
			rpUuid = ruu;

			reqBody = {
				"nickname": nickname,
				"id": id,
				"rawId": rawId,
				"type": type,
				"response": response,
				"getClientExtensionResults": getClientExtensionResults,
				"enabled": true
			};

			return myfetch(
				process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/attestation/result",
				{
					method: "POST",
					headers: {
						"Content-type": "application/json",
						"Accept": "application/json",
						"Authorization": "Bearer " + access_token
					},
					body: JSON.stringify(reqBody),
					returnAsJSON: true
				}
			);
		}).then((rspBody) => {
			// worked
			return getUsernameAndCredentialsResponse(req, null, false);
		}).then((ucr) => {
			result.body = ucr;
			sendAndroidResponse(rsp, result);
		}).catch((e) => {
			console.log(e);
			result.status = "failed";
			result.body = {"error": "androidRegisterResponse unexpected error"};
			sendAndroidResponse(rsp, result);
		});

	} else {
		result.status = "failed";
		result.body = { "error":"required parameters not present"};
		sendAndroidResponse(rsp, result);
	}
}

function androidRemoveKey(req, rsp) {
	logRequest("androidRemoveKey", req);
	var result = {
			"status": "ok",
			"body": {
			},
			"cookies" : [
			]
		};
	var username = req.cookies["username"];
	var userId = null;
	if (username != null) {
		// credId comes in on query string!
		var credId = req.query.credId;
		if (credId != null) {
			// remove it so long as it belongs to this user
			tm.getAccessToken(req)
			.then((at) => {
				access_token = at;

				// resolve username to userId
				return myfetch(
					process.env.CI_TENANT_ENDPOINT + "/v2.0/Users?" + new URLSearchParams({ "filter" : 'userName eq "' + username + '"' }),
					{
						method: "GET",
						headers: {
							"Accept": "application/scim+json",
							"Authorization": "Bearer " + access_token
						},
						returnAsJSON: true
					}
				);
			}).then((scimResponse) => {
				if (scimResponse && scimResponse.totalResults == 1 && scimResponse.Resources[0].active) {
					var user = scimResponse.Resources[0];
					var search = 'attributes/credentialId="' + credId + '"&userId="' + user.id + '"';

					// now get the registration - the search filter ensures ownership is also checked
					return myfetch(
						process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations?" + new URLSearchParams({ "search" : search }),
						{
							method: "GET",
							headers: {
								"Accept": "application/json",
								"Authorization": "Bearer " + access_token
							},
							returnAsJSON: true
						}
					);
				} else{
					throw "invalid or disabled user";
				}
			}).then((registrationsResponse) => {
				// delete the registration if returned
				//console.log("Received registrations response: " + JSON.stringify(registrationsResponse));

				if (registrationsResponse.total == 1) {
					var regId = registrationsResponse.fido2[0].id;

					// delete it
					return myfetch(
						process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + regId,
						{
							method: "DELETE",
							headers: {
								"Accept": "application/json",
								"Authorization": "Bearer " + access_token
							}
						}
					).then(() => {
						logger.logWithTS("Registration deleted: " + regId);
					});
				}
			}).then(() => {
				// delete complete if credId was valid, just return an empty JSON object response
				sendAndroidResponse(rsp, result);
			}).catch((e) => {
				console.log(e);
				result.status = "failed";
				result.body = {"error": "androidRemoveKey unexpected error"};
				sendAndroidResponse(rsp, result);
			});
		} else {
			result.status = "failed";
			result.body = { "error": "missing credId" };
			sendAndroidResponse(rsp, result);
		}
	} else {
		result.status = "failed";
		result.body = { "error": "no username supplied" };
		sendAndroidResponse(rsp, result);
	}		
}

function androidSigninRequest(req, rsp) {
	logRequest("androidSigninRequest", req);
	var result = {
		"status": "ok",
		"body": {
		},
		"cookies" : [
		]
	};

	// may or may not be already logged in
	var username = req.cookies["username"];


	var userId = null;

	tm.getAccessToken(req)
	.then((at) => {
		access_token = at;
		return rpIdTorpUuid(process.env.RPID);
	}).then((ruu) => {
		rpUuid = ruu;

		// if we have a username, resolve to check it's legit, and get userId
		if (username != null) {
			return myfetch(
				process.env.CI_TENANT_ENDPOINT + "/v2.0/Users?" + new URLSearchParams({ "filter" : 'userName eq "' + username + '"' }),
				{
					method: "GET",
					headers: {
						"Accept": "application/scim+json",
						"Authorization": "Bearer " + access_token
					},
					returnAsJSON: true
				}
			).then((scimResponse) => {
				if (scimResponse && scimResponse.totalResults == 1 && scimResponse.Resources[0].active) {
					userId = scimResponse.Resources[0].id;
				}
			});
		}
	}).then(() => {
		// prepare assertion options body for CI
		var reqBody = {
			"userVerification": "preferred"
		};

		if (userId != null) {
			reqBody["userId"] = userId;
		}

		if (req.body.attestation != null) {
			reqBody["attestation"] = req.body.attestation;
		}

		// call CI
		return myfetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/assertion/options",
			{
				method: "POST",
				headers: {
					"Content-type": "application/json",
					"Accept": "application/json",
					"Authorization": "Bearer " + access_token
				},
				body: JSON.stringify(reqBody),
				returnAsJSON: true
			}
		);
	}).then((rspBody) => {
		// remove these - the android app doesn't understand them
		delete rspBody["status"];
		delete rspBody["errorMessage"];
		delete rspBody["extensions"];

		//
		// TODO: If the request included a credId, and the allowCredentials list in the response contains it,
		// return only that one. I've never seen the demo app actually send a credId though...
		//		

		result.body = rspBody;
		sendAndroidResponse(rsp, result);
	}).catch((e) => {
		console.log(e);
		result.status = "failed";
		result.body = {"error": "androidSigninRequest unexpected error"};
		sendAndroidResponse(rsp, result);
	});
}

function androidSigninResponse(req, rsp) {
	logRequest("androidSigninResponse", req);
	var result = {
		"status": "ok",
		"body": {
		},
		"cookies" : [
		]
	};

	// we require these to be present
	var id = req.body.id;
	var rawId = req.body.rawId;
	var type = req.body.type;
	var response = req.body.response;

	if (id != null && rawId != null && type != null && response != null) {

		// validate the assertion via the FIDO2 server
		tm.getAccessToken(req)
		.then((at) => {
			access_token = at;
			return rpIdTorpUuid(process.env.RPID);
		}).then((ruu) => {
			rpUuid = ruu;

			reqBody = {
				"id": id,
				"rawId": rawId,
				"type": type,
				"response": response
			};

			return myfetch(
				process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/assertion/result",
				{
					method: "POST",
					headers: {
						"Content-type": "application/json",
						"Accept": "application/json",
						"Authorization": "Bearer " + access_token
					},
					body: JSON.stringify(reqBody),
					returnAsJSON: true
				}
			);
		}).then((rspBody) => {
			// worked - resolve userId to username and make sure they are real and still active
			return myfetch(
				process.env.CI_TENANT_ENDPOINT + "/v2.0/Users?" + new URLSearchParams({ "filter" : 'id eq "' + rspBody.userId + '"' }),
				{
					method: "GET",
					headers: {
						"Accept": "application/scim+json",
						"Authorization": "Bearer " + access_token
					},
					returnAsJSON: true
				}
			);
		}).then((scimResponse) => {
			if (scimResponse && scimResponse.totalResults == 1) {
				if (scimResponse.Resources[0].active) {
					// ok 
					return scimResponse.Resources[0].userName;
				} else {
					throw "User disabled";
				}
			} else {
				throw "User record not found";
			}
		}).then((username) => {
			result.cookies.push({"name":"signed-in", "value":"yes", "options": { "path":"/"}});
			result.cookies.push({"name":"username", "value": username, "options": { "path":"/"}});
			result.cookies.push({"name":"challenge", "value":"", "options":{"path":"/", "expires": (new Date(0))}});

			return getUsernameAndCredentialsResponse(req, username, false);
		}).then((ucr) => {
			result.body = ucr;
			sendAndroidResponse(rsp, result);
		}).catch((e) => {
			console.log(e);
			result.status = "failed";
			result.body = {"error": "androidSigninResponse unexpected error"};
			sendAndroidResponse(rsp, result);
		});

	} else {
		result.status = "failed";
		result.body = { "error":"required parameters not present"};
		sendAndroidResponse(rsp, result);
	}
}


function validateAccessToken(req) {
	let bearerToken = req.get('Authorization').match(/[Bb][Ee][Aa][Rr][Ee][Rr] (.*)/)[1];
	let introspectResponse = null;
	return tokenIntrospection(bearerToken)
	.then((ir) => {
		introspectResponse = ir;
		console.log("introspectResponse: " + JSON.stringify(introspectResponse));
		var url = process.env.CI_TENANT_ENDPOINT + "/v1.0/endpoint/default/userinfo";
		var options = {
			method: "POST",
			headers: {
				"Accept": "application/json",
				"Authorization": "Bearer " + bearerToken
			},
			returnAsJSON: true
		};

		return myfetch(
			url,
			options
		);
	}).then((uir) => {
		console.log("userinfoResponse: " + JSON.stringify(uir));
		let result = {
			bearerToken: bearerToken,
			introspect: introspectResponse,
			userinfo: uir
		};
		return result;
	});
}

/**
* Start of section dedicated to APIs used by the FIDO2App
*/

function fido2appIVCredsResponse(req, rsp) {
	validateAccessToken(req)
	.then((validationResult) => {
		console.log("validationResult: " + JSON.stringify(validationResult));
		rsp.json({
			"AZN_CRED_PRINCIPAL_NAME": validationResult.userinfo.sub,
			"email": validationResult.userinfo.email,
			"name": validationResult.userinfo.displayName /*validationResult.userinfo.preferred_username */
		});	
	}).catch((e) => {
		console.log(e);
		rsp.json({"AZN_CRED_PRINCIPAL_NAME": "unauthenticated"});
	});
}

function fido2appAttestationOptions(req, rsp) {
	let userId = null;
	let user_access_token = null;
	let bodyToSend = req.body;
	validateAccessToken(req)
	.then((validationResult) => {
		userId = validationResult.userinfo.sub;
		user_access_token = validationResult.bearerToken;
		return rpIdTorpUuid(process.env.RPID);
	}).then((rpUuid) => {
		// the CI body is slightly different from the FIDO server spec. 
		// instead of username we need to provide userId which is the CI IUI for the user.
		if (bodyToSend.username != null) {
			delete bodyToSend.username;
			bodyToSend.userId = userId;
		}

		let options = {
			method: "POST",
			headers: {
				"Content-type": "application/json",
				"Accept": "application/json",
				"Authorization": "Bearer " + user_access_token
			},
			returnAsJSON: true,
			body: JSON.stringify(bodyToSend)
		};
		logger.logWithTS("fido2appAttestationOptions.options: " + JSON.stringify(options));
		return myfetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/attestation/options",
			options
		);
	}).then((attestationOptionsResponse) => {
		// worked - add server spec status and error message fields
		let rspBody = attestationOptionsResponse;
		rspBody.status = "ok";
		rspBody.errorMessage = "";
		logger.logWithTS("fido2appAttestationOptions.success: " + JSON.stringify(rspBody));
		rsp.json(rspBody);
	}).catch((e)  => {
		handleErrorResponse("fido2appAttestationOptions", rsp, e, "Unable to proxy FIDO2 request");
	});
}

function fido2appAttestationResult(req, rsp) {
	let user_access_token = null;
	let bodyToSend = req.body;

	// when performing registrations, I want the registration 
	// enabled immediately so insert this additional option
	bodyToSend.enabled = true;

	validateAccessToken(req)
	.then((validationResult) => {
		user_access_token = validationResult.bearerToken;
		return rpIdTorpUuid(process.env.RPID);
	}).then((rpUuid) => {
		let options = {
			method: "POST",
			headers: {
				"Content-type": "application/json",
				"Accept": "application/json",
				"Authorization": "Bearer " + user_access_token
			},
			returnAsJSON: true,
			body: JSON.stringify(bodyToSend)
		};
		logger.logWithTS("fido2appAttestationResult.options: " + JSON.stringify(options));
		return myfetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/attestation/result",
			options
		);
	}).then((attestationResultResponse) => {
		// worked - add server spec status and error message fields
		let rspBody = attestationResultResponse;
		rspBody.status = "ok";
		rspBody.errorMessage = "";
		logger.logWithTS("fido2appAttestationResult.success: " + JSON.stringify(rspBody));
		rsp.json(rspBody);
	}).catch((e)  => {
		handleErrorResponse("fido2appAttestationResult", rsp, e, "Unable to proxy FIDO2 request");
	});
}

function fido2appAssertionOptions(req, rsp) {
	let userId = null;
	let user_access_token = null;
	let bodyToSend = req.body;
	validateAccessToken(req)
	.then((validationResult) => {
		userId = validationResult.userinfo.sub;
		user_access_token = validationResult.bearerToken;
		return rpIdTorpUuid(process.env.RPID);
	}).then((rpUuid) => {
		// the CI body is slightly different from the FIDO server spec. 
		// instead of username we need to provide userId which is the CI IUI for the user.
		if (bodyToSend.username != null) {
			delete bodyToSend.username;
			bodyToSend.userId = userId;
		}

		let options = {
			method: "POST",
			headers: {
				"Content-type": "application/json",
				"Accept": "application/json",
				"Authorization": "Bearer " + user_access_token
			},
			returnAsJSON: true,
			body: JSON.stringify(bodyToSend)
		};
		logger.logWithTS("fido2appAssertionOptions.options: " + JSON.stringify(options));
		return myfetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/assertion/options",
			options
		);
	}).then((assertionOptionsResponse) => {
		// worked - add server spec status and error message fields
		let rspBody = assertionOptionsResponse;
		rspBody.status = "ok";
		rspBody.errorMessage = "";
		logger.logWithTS("fido2appAssertionOptions.success: " + JSON.stringify(rspBody));
		rsp.json(rspBody);
	}).catch((e)  => {
		handleErrorResponse("fido2appAssertionOptions", rsp, e, "Unable to proxy FIDO2 request");
	});
}

function fido2appAssertionResult(req, rsp) {
	let user_access_token = null;
	let bodyToSend = req.body;
	validateAccessToken(req)
	.then((validationResult) => {
		user_access_token = validationResult.bearerToken;
		return rpIdTorpUuid(process.env.RPID);
	}).then((rpUuid) => {
		let options = {
			method: "POST",
			headers: {
				"Content-type": "application/json",
				"Accept": "application/json",
				"Authorization": "Bearer " + user_access_token
			},
			returnAsJSON: true,
			body: JSON.stringify(bodyToSend)
		};
		logger.logWithTS("fido2appAssertionResult.options: " + JSON.stringify(options));
		return myfetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/assertion/result",
			options
		);
	}).then((assertionResultResponse) => {
		// worked - add server spec status and error message fields
		let rspBody = assertionResultResponse;
		rspBody.status = "ok";
		rspBody.errorMessage = "";
		logger.logWithTS("fido2appAssertionResult.success: " + JSON.stringify(rspBody));
		return rspBody;
	}).then((rspBody) => {
		// just before we write the response unpack the authenticatorData that was used
		// in this request, and see if there are any txAuthSimple extensions in it
		let authenticatorDataStr = bodyToSend.response.authenticatorData;
		let unpackedAuthData = fidoutils.unpackAuthData(KJUR.b64toBA(KJUR.b64utob64(authenticatorDataStr)));
		console.log("unpackedAuthData: " + JSON.stringify(unpackedAuthData));		
		if (unpackedAuthData.status && unpackedAuthData.extensions != null && unpackedAuthData.extensions.txAuthSimple != null) {
			txnprocessing.storeTransactionForCredential(bodyToSend.id, unpackedAuthData.extensions.txAuthSimple, rspBody.attempted);
		}
		rsp.json(rspBody);
	}).catch((e)  => {
		handleErrorResponse("fido2appAssertionResult", rsp, e, "Unable to proxy FIDO2 request");
	});
}


module.exports = { 
	validateUsernamePassword: validateUsernamePassword,
	sendUserResponse: sendUserResponse, 
	deleteRegistration: deleteRegistration,
	registrationDetails: registrationDetails,
	proxyFIDO2ServerRequest: proxyFIDO2ServerRequest,
	validateFIDO2Login: validateFIDO2Login,
	androidAssetLinks: androidAssetLinks,
	androidUsername: androidUsername,
	androidPassword: androidPassword,
	androidGetKeys: androidGetKeys,
	androidRegisterRequest: androidRegisterRequest,
	androidRegisterResponse: androidRegisterResponse,
	androidRemoveKey: androidRemoveKey,
	androidSigninRequest: androidSigninRequest,
	androidSigninResponse: androidSigninResponse,
	fido2appIVCredsResponse: fido2appIVCredsResponse,
	fido2appAttestationOptions: fido2appAttestationOptions,
	fido2appAttestationResult: fido2appAttestationResult,
	fido2appAssertionOptions: fido2appAssertionOptions,
	fido2appAssertionResult: fido2appAssertionResult
};
