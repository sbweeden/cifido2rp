// server.js
// where your node app starts

// init project
const express = require('express');
const session = require('express-session');
const https = require('https');
const fs = require('fs');
const passport = require('passport');
const cookieParser = require("cookie-parser");
const oidcClient = require('openid-client');
const tm = require('./oauthtokenmanager.js');
const identityServices = require('./ciservices.js');
const app = express();

// set to ignore ssl cert errors when making requests
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

app.use(session({
	secret: process.env.SECRET,
	resave: false,
	saveUninitialized: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// http://expressjs.com/en/starter/static-files.html
app.use('/static', express.static('public'));

// For OIDC login
app.use(passport.initialize());
app.use(passport.session());

// check we can get OIDC information, and if we can, include that as a login option
oidcClient.Issuer.discover(process.env.CI_TENANT_ENDPOINT + "/oidc/endpoint/default/.well-known/openid-configuration")
.then((isvIssuer) => {
	//console.log('isvIssuer.metadata: ' + JSON.stringify(isvIssuer.metadata));

	let myClient = new isvIssuer.Client({
		client_id: process.env.OIDC_CLIENT_ID,
		client_secret: process.env.OIDC_CLIENT_SECRET,
		redirect_uris: [ "https://"+process.env.RPID+ (process.env.LOCAL_SSL_SERVER == "true" ? (":"+process.env.LOCAL_SSL_PORT) : "") + "/callback" ],
		response_types: ['code']
	});

	passport.use("oidc", new oidcClient.Strategy(
		// see https://github.com/panva/node-openid-client/blob/main/docs/README.md#strategy
		{
			client: myClient,
			params: {
				scope: "openid profile"
			},
			passReqToCallback: false,
			usePKCE: true
		},
		(tokenSet, userinfo, done) => {
			var data = {
				tokenSet: tokenSet,
				userinfo: userinfo
			};
			//console.log("OIDC callback function called with: " + JSON.stringify(data));
			return done(null, data);
		})
	);
}).then(() => {
	// setup the login URL
	app.use("/loginoidc", passport.authenticate("oidc"));
}).then(() => {
	// set up the OIDC callback URL
	app.use("/callback", 
		passport.authenticate("oidc", { failureRedirect: "/error" }),
		(req, res) => {
			//console.log("Callback post-authentication function called with req.user: " + JSON.stringify(req.user));
			req.session.username = req.user.userinfo.preferred_username;
			req.session.userDisplayName = req.user.userinfo.displayName;
			req.session.userSCIMId = req.user.userinfo.sub;
			req.session.tokenResponse = {
				expires_at_ms: (req.user.tokenSet.expires_at * 1000),
				expires_in: Math.round(((new Date(req.user.tokenSet.expires_at*1000)).getTime() - (new Date()).getTime())/1000),
				refresh_token: req.user.tokenSet.refresh_token,
				access_token: req.user.tokenSet.access_token
			};
			res.redirect('/');
		}
	);
});

passport.serializeUser((user, next) => {
	next(null, user);
});

passport.deserializeUser((obj, next) => {
	next(null, obj);
});




//console.log(process.env);

// http://expressjs.com/en/starter/basic-routing.html
app.get('/', (req, rsp) => {
  	rsp.sendFile(__dirname + '/views/index.html');
});

app.post('/login', (req, rsp) => {
	// make sure we switch to the client_credentials OAuth client
	identityServices.validateUsernamePassword(req, rsp);
});

app.get('/error', (req,rsp) => {
	rsp.sendFile(__dirname + '/views/error.html');
});

app.get('/test', (req,rsp) => {
	identityServices.testButton(req, rsp);
});

app.get('/logout', (req, rsp) => {
	req.logout(() => {
		req.session.destroy();
		rsp.json({"authenticated": false});  
	});
});

app.get('/me', (req, rsp) => {
	identityServices.sendUserResponse(req, rsp);
});

app.get('/registrationDetails', (req, rsp) => {
	identityServices.registrationDetails(req, rsp);
});

app.post('/deleteRegistration', (req, rsp) => {
	identityServices.deleteRegistration(req, rsp);
});

app.post('/attestation/options', (req, rsp) => {
	identityServices.proxyFIDO2ServerRequest(req,rsp,true,false);
});

app.post('/attestation/result', (req, rsp) => {
	identityServices.proxyFIDO2ServerRequest(req,rsp,false,false);
});

app.post('/assertion/options', (req, rsp) => {
	identityServices.proxyFIDO2ServerRequest(req,rsp,true,true);
});

app.post('/assertion/result', (req, rsp) => {
	identityServices.proxyFIDO2ServerRequest(req,rsp,false,false);
});

app.post('/assertion/login', (req, rsp) => {
	identityServices.validateFIDO2Login(req,rsp);
});

/*
 * Start section of URLs used by the android app
 */
app.get('/.well-known/assetlinks.json', (req, rsp) => {
	identityServices.androidAssetLinks(req, rsp);
});

app.post('/auth/username', (req, rsp) => {
	identityServices.androidUsername(req, rsp);
});

app.post('/auth/password', (req, rsp) => {
	identityServices.androidPassword(req, rsp);
});

app.post('/auth/getKeys', (req, rsp) => {
	identityServices.androidGetKeys(req, rsp);
});

app.post('/auth/registerRequest', (req, rsp) => {
	identityServices.androidRegisterRequest(req, rsp);
});

app.post('/auth/registerResponse', (req, rsp) => {
	identityServices.androidRegisterResponse(req, rsp);
});

app.post('/auth/removeKey', (req, rsp) => {
	identityServices.androidRemoveKey(req, rsp);
});

app.post('/auth/signinRequest', (req, rsp) => {
	identityServices.androidSigninRequest(req, rsp);
});

app.post('/auth/signinResponse', (req, rsp) => {
	identityServices.androidSigninResponse(req, rsp);
});

/*
 * End section of URLs used by the android app
 */

// listen for requests
if (process.env.LOCAL_SSL_SERVER == "true") {
	https.createServer({
	    key: fs.readFileSync('./cifido2rp.key.pem'),
	    cert: fs.readFileSync('./cifido2rp.crt.pem')
	}, app)
	.listen(process.env.LOCAL_SSL_PORT, function() {
	  	console.log('Your SSL app is listening on port ' + process.env.LOCAL_SSL_PORT);
	});
} else {
	const listener = app.listen(process.env.PORT, function() {
	  	console.log('Your app is listening on port ' + listener.address().port);
	});
}
