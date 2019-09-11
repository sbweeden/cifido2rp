/**
* Simply wrapper for an error message.
* Our client expects status "ok" or "failed" and if failed an errorMessage.
*
* See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverresponse
*
* Errors are always logged to allow correlation with the conformance tool test cases.
*/
function fido2Error(msg) {
	this.status = "failed";
   	this.errorMessage = msg;
   	console.log(JSON.stringify(this));
}

module.exports = { 
	fido2Error: fido2Error
};
