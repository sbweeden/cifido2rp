// server.js
// where your node app starts

// init project
const express = require('express');
const session = require('express-session');
const https = require('https');
const fs = require('fs');
const passport = require('passport');
const cookieParser = require("cookie-parser");
const oidcStrategy = require('passport-openidconnect').Strategy;
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
app.use(express.urlencoded());
app.use(cookieParser());

// http://expressjs.com/en/starter/static-files.html
app.use('/static', express.static('public'));

// For OIDC login
app.use(passport.initialize());
app.use(passport.session());

passport.use("oidc", new oidcStrategy({
	issuer: process.env.CI_TENANT_ENDPOINT + "/oidc/endpoint/default",
	authorizationURL: process.env.CI_TENANT_ENDPOINT + "/oidc/endpoint/default/authorize",
	tokenURL: process.env.CI_TENANT_ENDPOINT + "/oidc/endpoint/default/token",
	userInfoURL: process.env.CI_TENANT_ENDPOINT + "/oidc/endpoint/default/userinfo",
	clientID: process.env.OIDC_CLIENT_ID,
	clientSecret: process.env.OIDC_CLIENT_SECRET,
	callbackURL: "https://"+process.env.RPID+ (process.env.LOCAL_SSL_SERVER == "true" ? (":"+process.env.LOCAL_SSL_PORT) : "") +"/callback",
	scope: "openid profile"
	}, 
	(issuer, sub, profile, accessToken, refreshToken, done) => {
		var data = {
			issuer: issuer,
			sub: sub,
			profile: profile,
			accessToken: accessToken,
			refreshToken: refreshToken,
			done: done
		};
		console.log("OIDC callback function called with: " + JSON.stringify(data));
		tm.setTokenResponse({
			expires_at_ms: (new Date()).getTime() + (7200 * 1000),
			expires_in: 7200,
			refresh_token: refreshToken,
			access_token: accessToken
		});
		return done(null, profile);
	}
));

passport.serializeUser((user, next) => {
	next(null, user);
});

passport.deserializeUser((obj, next) => {
	next(null, obj);
});

app.use("/loginoidc", passport.authenticate("oidc"));

app.use("/callback", 
	passport.authenticate("oidc", { failureRedirect: "/error" }),
	(req, res) => {
		console.log("Callback post-authentication function called with req.user: " + JSON.stringify(req.user));
		req.session.username = req.user.displayName;
		req.session.userSCIMId = req.user.id;
		res.redirect('/');
	});

//console.log(process.env);

// http://expressjs.com/en/starter/basic-routing.html
app.get('/', (req, rsp) => {
  	rsp.sendFile(__dirname + '/views/index.html');
});

app.post('/login', (req, rsp) => {
	// make sure we switch to the client_credentials OAuth client
	tm.setTokenResponse(null);
	identityServices.validateUsernamePassword(req, rsp);
});

app.get('/error', (req,rsp) => {
	rsp.sendFile(__dirname + '/views/error.html');
});

app.get('/test', (req,rsp) => {
	identityServices.testButton(req, rsp);
});

app.get('/logout', (req, rsp) => {
	req.logout();
	req.session.destroy();
	// make sure that next session uses session-specific access token
	tm.setTokenResponse(null);
  	rsp.json({"authenticated": false});
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
