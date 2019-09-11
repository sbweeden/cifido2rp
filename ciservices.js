//
// ciservices - performs user and FIDO2 operations against IBM Cloud Identity
//
const KJUR = require('jsrsasign');
const cbor = require('cbor');
const requestp = require('request-promise-native');
const logger = require('./logging.js');
const tm = require('./oauthtokenmanager.js');
const fido2error = require('./fido2error.js');

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
	tm.getAccessToken()
	.then( (at) => {
		access_token = at;		
		return rpIdTorpUuid(process.env.RPID);
	}).then((rpUuid) => {
		var options = {
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + req.url,
			method: "POST",
			headers: {
				"Content-type": "application/json",
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			json: true,
			body: bodyToSend
		};
		logger.logWithTS("proxyFIDO2ServerRequest.options: " + JSON.stringify(options));
		return requestp(options);
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
	tm.getAccessToken().then((at) => {
		access_token = at;		
		return rpIdTorpUuid(process.env.RPID);
	}).then((rpUuid) => {
		return requestp({
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/assertion/result",
			method: "POST",
			headers: {
				"Content-type": "application/json",
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			json: true,
			body: bodyToSend
		});
	}).then((assertionResult) => {
		// FIDO2 login worked
		logger.logWithTS("validateFIDO2Login.assertionResult: " + JSON.stringify(assertionResult));

		// lookup user from id to make sure they are real and still active
		return requestp({
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Users",
			method: "GET",
			qs: { "filter" : 'id eq "' + assertionResult.userId + '"' },
			headers: {
				"Accept": "application/scim+json",
				"Authorization": "Bearer " + access_token
			},
			json: true
		});
	}).then((scimResponse) => {
		if (scimResponse && scimResponse.totalResults == 1) {
			if (scimResponse.Resources[0].active) {
				// ok to login
				req.session.userSCIMId = scimResponse.Resources[0].id;
				req.session.username = scimResponse.Resources[0].userName;

				return getUserResponse(req.session.username, req.session.userSCIMId);
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
			tm.getAccessToken().then((at) => {
				access_token = at;
				// first search for the suggested registration
				return requestp({
					url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + regId,
					method: "GET",
					headers: {
						"Accept": "application/json",
						"Authorization": "Bearer " + access_token
					},
					json: true
				});
			}).then((regToDelete) => {
				// is it owned by the currenty authenticated user
				if (regToDelete.userId == req.session.userSCIMId) {
					return requestp({
						url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + regId,
						method: "DELETE",
						headers: {
							"Accept": "application/json",
							"Authorization": "Bearer " + access_token
						},
						json: true
					}).then(() => {
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
			tm.getAccessToken().then((at) => {
				access_token = at;
				// first retrieve the suggested registration
				return requestp({
					url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + regId,
					method: "GET",
					headers: {
						"Accept": "application/json",
						"Authorization": "Bearer " + access_token
					},
					json: true
				});
			}).then((reg) => {
				logger.logWithTS("registrationDetails." + regId + " received: " + JSON.stringify(reg));
				// check it is owned by the currenty authenticated user
				if (reg.userId == req.session.userSCIMId) {
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

function validateUsernamePassword(req, rsp) {
	var username = req.body.username;
	var password = req.body.password;

	return tm.getAccessToken()
	.then((access_token) => {
		return requestp({
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Users/authentication",
			method: "POST",
			headers: {
				"Authorization": "Bearer " + access_token,
				"Content-type": "application/scim+json",
				"Accept": "application/scim+json"
			},
			json: true,
			body: {
				"userName" : username,
				"password": password,
				"schemas": ["urn:ietf:params:scim:schemas:ibm:core:2.0:AuthenticateUser"]
			}
		});
	}).then((scimResponse) => {
		// logged in ok
		req.session.username = username;
		req.session.userSCIMId = scimResponse.id;
		return getUserResponse(req.session.username, req.session.userSCIMId);
	}).then((userResponse) => {
		rsp.json(userResponse);
	}).catch((e)  => {
		logger.logWithTS("ciservices.validateUsernamePassword inside catch block with e: " + (e != null ? JSON.stringify(e): "null"));
		rsp.json(e);
	});
}

function updateRPMaps() {
	// reads all relying parties from discovery service updates local caches
	return tm.getAccessToken()
	.then((access_token) => {
		return requestp({
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/discover/fido2",
			method: "GET",
			headers: {
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			json: true
		});
	}).then((discoverResponse) => {
		rpUuidMap = [];
		rpIdMap = [];
		discoverResponse.fido2.relyingParties.forEach((rp) => {
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

function getUserResponse(username, userId) {
	var result = { "authenticated": true, "username": username, "credentials": []};
	var search = 'userId="' + userId + '"';
	// to futher filter results for just my rpId, add this
	search += '&attributes/rpId="'+process.env.RPID+'"';

	return tm.getAccessToken()
	.then((access_token) => { 

		var options = {
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations",
			method: "GET",
			qs: { "search" : search},
			headers: {
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			json: true
		};

		// This includes an example of how to measure the response time for a call
		var start = (new Date()).getTime();
		return requestp(options).then((r) => {
			var now = (new Date()).getTime();
			console.log("getUserResponse: call to get user registrations with options: " + JSON.stringify(options) + " took(msec): " + (now-start));
			return r;
		});
	}).then((registrationsResponse) => {
		return coerceCIRegistrationsToClientFormat(registrationsResponse);
	}).then((registrationsResponse) => {
		result.credentials = registrationsResponse.fido2;
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
		getUserResponse(req.session.username, req.session.userSCIMId)
		.then((userResponse) => {
			rsp.json(userResponse);
		}).catch((e)  => {
			handleErrorResponse("sendUserResponse", rsp, e, "Unable to get user registrations");
		});
	} else {
		rsp.json({"authenticated": false});
	}
}



module.exports = { 
	validateUsernamePassword: validateUsernamePassword,
	sendUserResponse: sendUserResponse, 
	deleteRegistration: deleteRegistration,
	registrationDetails: registrationDetails,
	proxyFIDO2ServerRequest: proxyFIDO2ServerRequest,
	validateFIDO2Login: validateFIDO2Login
};
