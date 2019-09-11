# cifido2rp

This is a demonstration Node.js application that shows consumption of basic user and FIDO2 APIs from a cloud identity tenant.

To use:

1. Update your local hosts file to have www.cifido2rp.com as a hostname alias (I do this for the loopback address 127.0.0.1) where your Node application is going to listen.
1. Make sure you have Node.js installed.
1. clone the repo into a directory and cd to that directory
1. npm install
1. cp .env.example to .env 
1. edit the .env file and at a minimum update CI_TENANT_ENDPOINT, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET. The OpenID Connect related parameters are optional. If you don't set up an OIDC application in Cloud Identity, then you will be limited to username/password login.
1. npm run start_local


CI tenant requirements:

1. You need to create a cloud directory user, with a password, and know that password. This user will be needed to login to the Node.js application.
1. Create an API client_id and client_secret (these go into the .env file) with the following entitlements:
    1. Authenticate any user
    1. Manage second-factor authentication enrollment for all users
    1. Manage second-factor authentication method configuration
    1. Manage users and standard groups
1. Create a FIDO2 RP definition for the RPID www.cifido2rp.com. Optionally upload metadata.

