// txnprocessing.js - demo APIs for storing and retrieving the transactions
const KJUR = require('jsrsasign');
const logger = require('./logging.js');
const fidoutils = require('./fidoutils.js');

// in memory cache for demo
var _txnCache = {};

/**
 * In-memory storage of 5 most recent transactions
 */
function storeTransactionForCredential(credId, txt, timestamp) {
	// temporary storage of recent transactions
	let lookupKey = "txns_" + KJUR.BAtohex(fidoutils.sha256(KJUR.b64toBA(KJUR.utf8tob64(credId))));
	let txnObj = {
		timestamp: timestamp,
		txt: txt
	};
	logger.logWithTS("storeTransactionForCredential: credId: " + credId + " txnObj: " + JSON.stringify(txnObj) + " timestamp: " + timestamp);
	let existingTxnsStr = _txnCache[lookupKey];
	let existingTxns = [];
	if (existingTxnsStr != null) {
		existingTxns = JSON.parse(''+existingTxnsStr);
	}
	existingTxns.unshift(txnObj);
	if (existingTxns.length > 5) {
		existingTxns = existingTxns.slice(0,5);
	}
	// store for an hour
	_txnCache[lookupKey] = JSON.stringify(existingTxns);
}

function getTransactionsForCredentialID(credId) {
    let result = [];
    let lookupKey = "txns_" + KJUR.BAtohex(fidoutils.sha256(KJUR.b64toBA(KJUR.utf8tob64(credId))));
    let txnsStr = _txnCache[lookupKey];
    if (txnsStr != null) {
        result = JSON.parse(txnsStr);
    }
    return result;
}

module.exports = { 
    storeTransactionForCredential: storeTransactionForCredential,
    getTransactionsForCredentialID: getTransactionsForCredentialID
};
