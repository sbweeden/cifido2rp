// fidoutils - collection of helper APIs.
const KJUR = require('jsrsasign');
const cbor = require('cbor');
const logger = require('./logging.js');


/**
 * Returns the bytes of a sha256 message digest of either a string or byte array
 * This is used when building the signature base string to verify
 * registration data.
 */
function sha256(data) {
	var md = new KJUR.crypto.MessageDigest({
		alg : "sha256",
		prov : "cryptojs"
	});
	if (Array.isArray(data)) {
		md.updateHex(KJUR.BAtohex(data));
	} else {
		md.updateString(data);
	}
	return KJUR.b64toBA(KJUR.hex2b64(md.digest()));
}

/**
 * Extracts the bytes from an array beginning at index start, and continuing until 
 * index end-1 or the end of the array is reached. Pass -1 for end if you want to 
 * parse till the end of the array.
 */
function bytesFromArray(o, start, end) {
	// o may be a normal array of bytes, or it could be a JSON encoded Uint8Array
	var len = o.length;
	if (len == null) {
		len = Object.keys(o).length;
	}
	
	var result = [];
	for (var i = start; (end == -1 || i < end) && (i < len); i++) {
		result.push(o[i]);
	}
	return result;
}

/*
* returns true if o's keys are only "0", "1", ... "n"
*/
function integerKeys(o) {
	var result = false;
	if (o != null) {
		var oKeys = Object.keys(o);
		var intArray = [...Array(oKeys.length).keys()];
		var result = true;
		for (var i = 0; i < intArray.length && result; i++) {
			if (oKeys[i] != ''+intArray[i]) {
				result = false;
			}
		}
	}
	return result;
}

/*
* Recursively inspect every element of o and if it is an object which is not already 
* an Array and who's keys are only the numbers from 0...x then assume that object is an
* ArrayBuffer and convert to BA.
*/
function convertArrayBuffersToByteArrays(o) {
	if (o != null) {
		Object.keys(o).forEach((k)=> {
			if (typeof o[k] == "object") {
				if (!Array.isArray(o[k]) && integerKeys(o[k])) {
					o[k] = bytesFromArray(o[k], 0, -1);
				} else {
					convertArrayBuffersToByteArrays(o[k]);
				}
			}
		});
	}
	return o;
}

/**
 * Converts the base64 encoded public key representation stored by IBM to a COSE key
 */
function publicKeyStringToCOSEKey(s) {
    return convertArrayBuffersToByteArrays(cbor.decodeFirstSync(KJUR.b64tohex(s)));
}

/**
* Converts a JSON COSE Key to a KJUR public key variable
*/
function coseKeyToPublicKey(k) {
	var result = null;

	if (k != null) {
		// see https://tools.ietf.org/html/rfc8152
		// and https://www.iana.org/assignments/cose/cose.xhtml
		var kty = k["1"];
		var alg = k["3"];

		if (kty == 1) {
			// EdDSA key type
			validEDAlgs = [ -8 ];
			if (validEDAlgs.indexOf(alg) >= 0) {
				var crvMap = {
						"6" : "Ed25519",
						"7" : "Ed448"
					};
					var crv = crvMap['' + k["-1"]];
					if (crv != null) {
						logger.logWithTS("No support for EdDSA keys");
					} else {
						logger.logWithTS("Invalid crv: " + k["-1"] + " for ED key type");
					}

			} else {
				logger.logWithTS("Invalid alg: " + alg + " for ED key type");
			}
		} else if (kty == 2) {
			// EC key type
			validECAlgs = [ -7, -35, -36 ];

			if (validECAlgs.indexOf(alg) >= 0) {
				var crvMap = {
					"1" : "P-256",
					"2" : "P-384",
					"3" : "P-521" // this is not a typo. It is 521
				};
				var crv = crvMap['' + k["-1"]];
				if (crv != null) {
					// ECDSA
					var xCoordinate = bytesFromArray(k["-2"], 0, -1);
					var yCoordinate = bytesFromArray(k["-3"], 0, -1);

					if (xCoordinate != null && xCoordinate.length > 0
							&& yCoordinate != null && yCoordinate.length > 0) {
						result = KJUR.KEYUTIL.getKey({
							"kty" : "EC",
							"crv" : crv,
							"x" : KJUR.hextob64(KJUR.BAtohex(xCoordinate)),
							"y" : KJUR.hextob64(KJUR.BAtohex(yCoordinate))
						});
					} else {
						logger.logWithTS("Invalid x or y co-ordinates for EC key type");
					}
				} else {
					logger.logWithTS("Invalid crv: " + k["-1"] + " for EC key type");
				}
			} else {
				logger.logWithTS("Invalid alg: " + alg + " for EC key type");
			}
		} else if (kty == 3) {
			// RSA key type
			validRSAAlgs = [ -37, -38, -39, -257, -258, -259, -65535 ];
			if (validRSAAlgs.indexOf(alg) >= 0) {
				var n = bytesFromArray(k["-1"], 0, -1);
				var e = bytesFromArray(k["-2"], 0, -1);
				if (n != null && n.length > 0 && e != null && e.length > 0) {
					result = KJUR.KEYUTIL.getKey({
						"kty" : "RSA",
						"n" : KJUR.hextob64(KJUR.BAtohex(n)),
						"e" : KJUR.hextob64(KJUR.BAtohex(e))
					});
				} else {
					logger.logWithTS("Invalid n or e values for RSA key type");
				}
			} else {
				logger.logWithTS("Invalid alg: " + alg + " for RSA key type");
			}
		} else {
			logger.logWithTS("Unsupported key type: " + kty);
		}
	}
	return result;
}

/**
* Converts a KJUR public key object to a PEM string
*/
function publicKeyToPEM(pk) {
	var result = "";
	if (pk instanceof KJUR.RSAKey) {
		result = KJUR.KEYUTIL.getPEM(pk);
	} else if (pk instanceof KJUR.crypto.ECDSA) {
		result = certToPEM(KJUR.b64toBA(KJUR.hextob64(pk.pubKeyHex)));
	}
	return result;			
}

/**
 * Converts the bytes of an asn1-encoded X509 ceritificate or raw public key
 * into a PEM-encoded cert string
 */
function certToPEM(cert) {
	var keyType = "CERTIFICATE";
	asn1key = cert;

	if (cert != null && cert.length == 65 && cert[0] == 0x04) {
		// this is a raw public key - prefix with ASN1 metadata
		// SEQUENCE {
		// SEQUENCE {
		// OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
		// OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
		// }
		// BITSTRING <raw public key>
		// }
		// We just need to prefix it with constant 26 bytes of metadata
		asn1key = KJUR.b64toBA(KJUR.hextob64("3059301306072a8648ce3d020106082a8648ce3d030107034200"));
		Array.prototype.push.apply(asn1key, cert);
		keyType = "PUBLIC KEY";
	}
	var result = "-----BEGIN " + keyType + "-----\n";
	var b64cert = KJUR.hextob64(KJUR.BAtohex(asn1key));
	for (; b64cert.length > 64; b64cert = b64cert.slice(64)) {
		result += b64cert.slice(0, 64) + "\n";
	}
	if (b64cert.length > 0) {
		result += b64cert + "\n";
	}
	result += "-----END " + keyType + "-----\n";
	return result;
}

/**
 * Convert a 4-byte array to a uint assuming big-endian encoding
 * 
 * @param buf
 */
function bytesToUInt32BE(buf) {
	var result = 0;
	if (buf != null && buf.length == 4) {
		result = ((buf[0] & 0xFF) << 24) | ((buf[1] & 0xFF) << 16) | ((buf[2] & 0xFF) << 8) | (buf[3] & 0xFF);
		return result;
	}
	return result;
}

/*
* Override the CBOR decode method with a slightly modified version that handles remaining bytes in a 
* way that allows implementation of CBOR.decodeVariable
*/
cbor.decode = function(data, tagger, simpleValue) {
	var dataView = new DataView(data);
	var offset = 0;
  
	if (typeof tagger !== "function")
	  tagger = function(value) { return value; };
	if (typeof simpleValue !== "function")
	  simpleValue = function() { return undefined; };
  
	function commitRead(length, value) {
	  offset += length;
	  return value;
	}
	function readArrayBuffer(length) {
	  return commitRead(length, new Uint8Array(data, offset, length));
	}
	function readFloat16() {
	  var tempArrayBuffer = new ArrayBuffer(4);
	  var tempDataView = new DataView(tempArrayBuffer);
	  var value = readUint16();
  
	  var sign = value & 0x8000;
	  var exponent = value & 0x7c00;
	  var fraction = value & 0x03ff;
  
	  if (exponent === 0x7c00)
		exponent = 0xff << 10;
	  else if (exponent !== 0)
		exponent += (127 - 15) << 10;
	  else if (fraction !== 0)
		return (sign ? -1 : 1) * fraction * POW_2_24;
  
	  tempDataView.setUint32(0, sign << 16 | exponent << 13 | fraction << 13);
	  return tempDataView.getFloat32(0);
	}
	function readFloat32() {
	  return commitRead(4, dataView.getFloat32(offset));
	}
	function readFloat64() {
	  return commitRead(8, dataView.getFloat64(offset));
	}
	function readUint8() {
	  return commitRead(1, dataView.getUint8(offset));
	}
	function readUint16() {
	  return commitRead(2, dataView.getUint16(offset));
	}
	function readUint32() {
	  return commitRead(4, dataView.getUint32(offset));
	}
	function readUint64() {
	  return readUint32() * POW_2_32 + readUint32();
	}
	function readBreak() {
	  if (dataView.getUint8(offset) !== 0xff)
		return false;
	  offset += 1;
	  return true;
	}
	function readLength(additionalInformation) {
	  if (additionalInformation < 24)
		return additionalInformation;
	  if (additionalInformation === 24)
		return readUint8();
	  if (additionalInformation === 25)
		return readUint16();
	  if (additionalInformation === 26)
		return readUint32();
	  if (additionalInformation === 27)
		return readUint64();
	  if (additionalInformation === 31)
		return -1;
	  throw "Invalid length encoding";
	}
	function readIndefiniteStringLength(majorType) {
	  var initialByte = readUint8();
	  if (initialByte === 0xff)
		return -1;
	  var length = readLength(initialByte & 0x1f);
	  if (length < 0 || (initialByte >> 5) !== majorType)
		throw "Invalid indefinite length element";
	  return length;
	}
  
	function appendUtf16Data(utf16data, length) {
	  for (var i = 0; i < length; ++i) {
		var value = readUint8();
		if (value & 0x80) {
		  if (value < 0xe0) {
			value = (value & 0x1f) <<  6
				  | (readUint8() & 0x3f);
			length -= 1;
		  } else if (value < 0xf0) {
			value = (value & 0x0f) << 12
				  | (readUint8() & 0x3f) << 6
				  | (readUint8() & 0x3f);
			length -= 2;
		  } else {
			value = (value & 0x0f) << 18
				  | (readUint8() & 0x3f) << 12
				  | (readUint8() & 0x3f) << 6
				  | (readUint8() & 0x3f);
			length -= 3;
		  }
		}
  
		if (value < 0x10000) {
		  utf16data.push(value);
		} else {
		  value -= 0x10000;
		  utf16data.push(0xd800 | (value >> 10));
		  utf16data.push(0xdc00 | (value & 0x3ff));
		}
	  }
	}
  
	function decodeItem() {
	  var initialByte = readUint8();
	  var majorType = initialByte >> 5;
	  var additionalInformation = initialByte & 0x1f;
	  var i;
	  var length;
  
	  if (majorType === 7) {
		switch (additionalInformation) {
		  case 25:
			return readFloat16();
		  case 26:
			return readFloat32();
		  case 27:
			return readFloat64();
		}
	  }
  
	  length = readLength(additionalInformation);
	  if (length < 0 && (majorType < 2 || 6 < majorType))
		throw "Invalid length";
  
	  switch (majorType) {
		case 0:
		  return length;
		case 1:
		  return -1 - length;
		case 2:
		  if (length < 0) {
			var elements = [];
			var fullArrayLength = 0;
			while ((length = readIndefiniteStringLength(majorType)) >= 0) {
			  fullArrayLength += length;
			  elements.push(readArrayBuffer(length));
			}
			var fullArray = new Uint8Array(fullArrayLength);
			var fullArrayOffset = 0;
			for (i = 0; i < elements.length; ++i) {
			  fullArray.set(elements[i], fullArrayOffset);
			  fullArrayOffset += elements[i].length;
			}
			return fullArray;
		  }
		  return readArrayBuffer(length);
		case 3:
		  var utf16data = [];
		  if (length < 0) {
			while ((length = readIndefiniteStringLength(majorType)) >= 0)
			  appendUtf16Data(utf16data, length);
		  } else
			appendUtf16Data(utf16data, length);
		  return String.fromCharCode.apply(null, utf16data);
		case 4:
		  var retArray;
		  if (length < 0) {
			retArray = [];
			while (!readBreak())
			  retArray.push(decodeItem());
		  } else {
			retArray = new Array(length);
			for (i = 0; i < length; ++i)
			  retArray[i] = decodeItem();
		  }
		  return retArray;
		case 5:
		  var retObject = {};
		  for (i = 0; i < length || length < 0 && !readBreak(); ++i) {
			var key = decodeItem();
			retObject[key] = decodeItem();
		  }
		  return retObject;
		case 6:
		  return tagger(decodeItem(), length);
		case 7:
		  switch (length) {
			case 20:
			  return false;
			case 21:
			  return true;
			case 22:
			  return null;
			case 23:
			  return undefined;
			default:
			  return simpleValue(length);
		  }
	  }
	}
  
	var ret = decodeItem();
  
	/*
	 * Here is the modification: deal with remaining bytes a different way so we can implement decodeVariable
	 */
	//if (offset !== datalen) {
	//  throw "Remaining bytes";
	//}
	if (offset !== data.byteLength) {
		var result = {};
		result["decodedObj"] = ret;
		result["datalen"] = data.byteLength;
		result["offset"] = offset;
		throw result;
	  }
  
	return ret;
}
  
/*
* Added this extra CBOR function to allow extraction of CBOR from a larger byte array
*/
cbor.decodeVariable = function(data, tagger, simpleValue) {
    try {
        var result = { "decodedObj": CBOR.decode(data, tagger, simpleValue), "offset": -1 };
        return result;
    } catch (e) {
        if (e["decodedObj"] != null && e["offset"] != null) {
            // this is a partial decode with remaining bytes
            return e;
        } else {
            throw e;
        }
    }
}

/**
 * Unpacks an authenticatorData payload to allow introspection and subsequent 
 * processing of the extensions after the assertion payload has been validated 
 * by a FIDO server.
 */
function unpackAuthData(authDataBytes) {
	var result = { 
		"status": false, 
		"rawBytes": null,
		"rpIdHashBytes": null, 
		"flags": 0, 
		"counter": 0, 
		"attestedCredData": null,
		"extensions": null
	};
	
	result["rawBytes"] = authDataBytes;
	
	if (authDataBytes != null && authDataBytes.length >= 37) {
		result["rpIdHashBytes"] = bytesFromArray(authDataBytes, 0, 32);
		result["flags"] = authDataBytes[32];
		result["counter"] = bytesToUInt32BE(bytesFromArray(authDataBytes, 33, 37));
				
		var nextByteIndex = 37;
		
		// check flags to see if there is attested cred data and/or extensions
		
		// bit 6 of flags - Indicates whether the authenticator added attested credential data.
		if (result["flags"] & 0x40) {
			result["attestedCredData"] = {};
			
			// are there enough bytes to read aaguid?
			if (authDataBytes.length >= (nextByteIndex + 16)) {
				result["attestedCredData"]["aaguid"] = bytesFromArray(authDataBytes, nextByteIndex, (nextByteIndex+16));
				nextByteIndex += 16;
				
				// are there enough bytes for credentialIdLength?
				if (authDataBytes.length >= (nextByteIndex + 2)) {
					var credentialIdLengthBytes = bytesFromArray(authDataBytes, nextByteIndex, (nextByteIndex+2));
					nextByteIndex += 2;
					var credentialIdLength = credentialIdLengthBytes[0] * 256 + credentialIdLengthBytes[1] 
					result["attestedCredData"]["credentialIdLength"] = credentialIdLength;
					
					// are there enough bytes for the credentialId?
					if (authDataBytes.length >= (nextByteIndex + credentialIdLength)) {
						result["attestedCredData"]["credentialId"] = bytesFromArray(authDataBytes, nextByteIndex, (nextByteIndex+credentialIdLength));
						nextByteIndex += credentialIdLength;
						
						var remainingBytes = bytesFromArray(authDataBytes, nextByteIndex, -1);
						
						//
						// try CBOR decoding the remaining bytes. 
						// NOTE: There could be both credentialPublicKey and extensions objects
						// so we use this special decodeVariable that Shane wrote to deal with
						// remaining bytes.
						//
						try {
							var decodeResult = cbor.decodeVariable((new Uint8Array(remainingBytes)).buffer);
							result["attestedCredData"]["credentialPublicKey"] = decodeResult["decodedObj"];
							nextByteIndex += (decodeResult["offset"] == -1 ? remainingBytes.length : decodeResult["offset"]);
						} catch (e) {
							logger.logWithTS("Error CBOR decoding credentialPublicKey: " + e);
							nextByteIndex = -1; // to force error checking
						}
					} else {
						logger.logWithTS("unPackAuthData encountered authDataBytes not containing enough bytes for credentialId in attested credential data");
					}					
				} else {
					logger.logWithTS("unPackAuthData encountered authDataBytes not containing enough bytes for credentialIdLength in attested credential data");
				}				
			} else {
				logger.logWithTS("unPackAuthData encountered authDataBytes not containing enough bytes for aaguid in attested credential data");
			}
		}
		
		// bit 7 of flags - Indicates whether the authenticator has extensions.
		if (nextByteIndex > 0 && result["flags"] & 0x80) {
			try {
				result["extensions"] = cbor.decode((new Uint8Array(bytesFromArray(authDataBytes, nextByteIndex, -1))).buffer);
				// must have worked
				nextByteIndex = authDataBytes.length;
			} catch (e) {
				logger.logWithTS("Error CBOR decoding extensions");
			}
		}
		
		// we should be done - make sure we processed all the bytes
		if (nextByteIndex == authDataBytes.length) {
			result["status"] = true;
		} else {
			logger.logWithTS("Remaining bytes in unPackAuthData. nextByteIndex: " + nextByteIndex + " authDataBytes.length: " + authDataBytes.length);
		}
	} else {
		logger.logWithTS("unPackAuthData encountered authDataBytes not at least 37 bytes long. Actual length: " + authDataBytes.length);
	}

	return result;
}

module.exports = { 
    sha256:sha256,
    publicKeyStringToCOSEKey: publicKeyStringToCOSEKey,
    coseKeyToPublicKey: coseKeyToPublicKey,
    publicKeyToPEM: publicKeyToPEM,
	unpackAuthData: unpackAuthData
};
