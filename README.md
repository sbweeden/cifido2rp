# cifido2rp

This is a demonstration Node.js application that shows consumption of basic user and FIDO2 APIs from a cloud identity tenant.

There is a companion blog article I've written about this application which includes more detailed instructions and screenshots for how to set up the Cloud Identity tenant, and example runtime flows here:

https://community.ibm.com/community/user/security/blogs/shane-weeden1/2019/09/16/cloud-identity-fido2-consuming-fido2-as-a-service

To use:

1. Update your local hosts file to have www.cifido2rp.com as a hostname alias (I do this for the loopback address 127.0.0.1) where your Node application is going to listen.
1. Make sure you have Node.js installed.
1. clone the repo into a directory and cd to that directory
1. npm install
1. cp .env.example to .env 
1. edit the .env file and at a minimum update CI_TENANT_ENDPOINT, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET. The OpenID Connect related parameters are optional. If you don't set up an OIDC application in Cloud Identity, then you will be limited to username/password login.
1. npm run start_local


CI tenant requirements:

1. You need a cloud directory user, with a password, and know that password. This user will be needed to login to the Node.js application. Alternatively you can use OpenID Connect login for single-signon, and this will permit a user in Cloud Identity from any Identity Source (not just cloud directory users with a password).
1. Create an API client_id and client_secret (these go into the .env file) with the following entitlements:
    1. Authenticate any user
    1. Manage second-factor authentication enrollment for all users
    1. Manage users and standard groups
1. Create a FIDO2 RP definition for the RPID www.cifido2rp.com. Optionally upload metadata.
1. Optionally create an OpenID Connect application configuration for the demonstration application.

## Other notes
Inspiration for how to create certificate files from: https://steffodimfelt.medium.com/how-to-make-node-js-running-https-localhost-on-macos-67b0840ad4c5

