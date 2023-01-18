using System;
using System.Threading.Tasks;

namespace ForceDotNetJwtCompanion;

/// <summary>
/// IJwtAuthenticationClient
///
/// HTTP handling and orchestration of JWT OAuth Flow with Salesforce.
/// 
/// </summary>
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