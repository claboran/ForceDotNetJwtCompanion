# ForceDotNetJwtCompanion
*This project is not offered, sponsored or endorsed by Salesforce.*
> DotNet Authorization of an Salesforce Org with OAuth 2.0 JWT Bearer Flow.

It is undesired for server to server communication to maintain passwords and client secrets of a Connected App
for several reasons:

* Dealing with plain text passwords, security tokens and client secrets in external applications weakens security
* Difficult to maintain (Security Tokens need a refresh)
* Connecting to many Org's from an external application will increase maintenance trouble

## Where to use it
You have a DotNet application being connected to your Salesforce Org's (a so called Connected App).
Several great frameworks are available for doing that job (thanks guys for your amazing work):
* [Force.com-Toolkit-for-NET](https://github.com/wadewegner/Force.com-Toolkit-for-NET)
* [NetCoreForce](https://github.com/anthonyreilly/NetCoreForce)

*Both libraries currently do not support OAuth 2.0 JWT Bearer Flow!*

> The library is supposed to work as a "Companion" to obtain an access token with OAuth 2.0 JWT Bearer Flow. It has never been thought as a replacement!
## Target Framework
.NET Standard 2.1

## How to use it
First things first - prepare your Org. Everything to know could be found here:

[Salesforce Developer guide: Authorize an Org Using the JWT Bearer Flow](https://developer.salesforce.com/docs/atlas.en-us.sfdx_dev.meta/sfdx_dev/sfdx_dev_auth_jwt_flow.htm#sfdx_dev_auth_jwt_flow)

### Generate keys

[Salesforce generate key](https://developer.salesforce.com/docs/atlas.en-us.sfdx_dev.meta/sfdx_dev/sfdx_dev_auth_key_and_cert.htm)

This is how I generated the private key and certificates for testing (just follow along the documentation):
```bash
cd ForceDotNetJwtCompanionTest/TestKeys 
openssl genrsa -des3 -passout pass:secret -out server.pass.key 2048
openssl rsa -passin pass:secret -in server.pass.key -out server.key
openssl req -new -key server.key -out server.csr
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
# in case you lost your encrypted key
openssl rsa -des3 -in .\server.key  -out .\server.key.enc
```
[Upload the crt file](https://developer.salesforce.com/docs/atlas.en-us.sfdx_dev.meta/sfdx_dev/sfdx_dev_auth_connected_app.htm)

> Private keys are currently supported in PEM format only!

### How to use it in your code
#### Public Api
```csharp
    public interface IJwtAuthenticationClient : IDisposable
    {
        string InstanceUrl { get; set; }
        string AccessToken { get; set; }
        string Id { get; set; }
        string ApiVersion { get; set; }

        /// <summary>
        /// JwtUnencryptedPrivateKeyAsync
        ///
        /// Obtain access token with unencrypted private key (not recommended)
        /// Token Endpoint: https://login.salesforce.com/services/oauth2/token (production) 
        /// </summary>
        /// <param name="clientId">ClientId of the Connected App aka Consumer Key</param>
        /// <param name="key">Private key as string, it is not required to remove header and footer</param>
        /// <param name="username">Salesforce username</param>
        Task JwtUnencryptedPrivateKeyAsync(string clientId, string key, string username);
        /// <summary>
        /// JwtPrivateKeyAsync
        /// 
        /// Obtain access token with encrypted private key
        /// Token Endpoint: https://login.salesforce.com/services/oauth2/token (production) 
        /// </summary>
        /// <param name="clientId">ClientId of the Connected App aka Consumer Key</param>
        /// <param name="key">Private key as string, it is not required to remove header and footer</param>
        /// <param name="passphrase">Passphrase of the private key</param>
        /// <param name="username">Salesforce username</param>
        Task JwtPrivateKeyAsync(string clientId, string key, string passphrase, string username);
        /// <summary>
        /// JwtUnencryptedPrivateKeyAsync
        ///
        /// Obtain access token with unencrypted private key (not recommended)
        /// with token endpoint
        /// </summary>
        /// <param name="clientId">ClientId of the Connected App aka Consumer Key</param>
        /// <param name="key">Private key as string, it is not required to remove header and footer</param>
        /// <param name="username">Salesforce username</param>
        /// <param name="tokenEndpoint">TokenEndpointUrl e.g. https://test.salesforce.com/services/oauth2/token</param>
        Task JwtUnencryptedPrivateKeyAsync(string clientId, string key, string username, string tokenEndpoint);
        /// <summary>
        /// JwtPrivateKeyAsync
        ///
        /// Obtain access token with encrypted private key
        /// with token endpoint
        /// </summary>
        /// <param name="clientId">ClientId of the Connected App aka Consumer Key</param>
        /// <param name="key">Private key as string, it is not required to remove header and footer</param>
        /// <param name="passphrase">Passphrase of the private key</param>
        /// <param name="username">Salesforce username</param>
        /// <param name="tokenEndpoint">TokenEndpointUrl e.g. https://test.salesforce.com/services/oauth2/token</param>
        Task JwtPrivateKeyAsync(string clientId, string key, string passphrase, string username, string tokenEndpoint);
    }
```
Usage in code:
```csharp
var apiVersion = "v50.0";
var privateKey = "your_private_loaded_from_somewhere";
var passPhrase = "your_secret_passphrase_loaded_from_somewhere";
var authClient = new JwtAuthenticationClient(apiVersion);

await authClient.JwtPrivateKeyAsync(
                "your_consumer_key", 
                privateKey,
                passPhrase, 
                "user@yourorganisation.com", 
                "https://test.salesforce.com/services/oauth2/token"
                );
var accessToken = authClient.AccessToken;
// use your access token
```
## Implementation
### General
The implementation is based on the Java example provided by Salesforce:

[Salesforce: implement JWT in Java](https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm&type=5)

> Cryptographic work is based on the awful [BOUNCY CASTLE PROJECT](https://www.bouncycastle.org/csharp/index.html)  
### Testing
All testing is done without accessing a real Salesforce Org. I have used the amazing [DotNet Testcontainers library](https://github.com/HofmeisterAn/dotnet-testcontainers) of Andre Hofmeister to provide a more realistic test scenario for
JwtAuthenticationClient.
The Mock Test server is based on node.js and the Express framework. You have to build a local docker image if you want
to run the tests on your own.

How to create the docker image BEFORE you run the test:
```bash
cd ForceDotNetJwtCompanion/express-test-docker
npm install
npm run build-local-docker-image
```
## License
Licensed under the MIT license.

## Open issues
* Needs some real life testing
* Implement JTI to prevent JWT replay attacks
* Improve comments in code
* CI/CD
* nuget :-) ...

## Dependencies
* Newtonsoft.Json
* BouncyCastle.NetCore
* DotNet.Testcontainers
* Microsoft.NET.Test.Sdk
* xunit
* nodejs v14.*
* Express and BodyParser

## Misc
Developed with [Jetbrains Rider](https://www.jetbrains.com/rider/) under Linux - what a cool experience...
