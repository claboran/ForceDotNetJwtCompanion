using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using ForceDotNetJwtCompanion.Models;
using ForceDotNetJwtCompanion.Util;
using Newtonsoft.Json;

namespace ForceDotNetJwtCompanion
{
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
    
    public class JwtAuthenticationClient : IJwtAuthenticationClient
    {
        public string InstanceUrl { get; set; }
        public string AccessToken { get; set; }
        public string Id { get; set; }
        public string ApiVersion { get; set; }

        private const string UserAgent = "forcedotnet-jwt-companion";
        private const string TokenRequestEndpointUrl = "https://login.salesforce.com/services/oauth2/token";
        private const string GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
        private const string ProdAudience = "https://login.salesforce.com";
        private const string TestAudience = "https://test.salesforce.com";
        
        private readonly HttpClient _httpClient;
        private readonly bool _disposeHttpClient;
        private readonly bool _isProd;

        public JwtAuthenticationClient(
            string apiVersion = "v50.0", 
            bool isProd = true
            ) : this(new HttpClient(), apiVersion, isProd)
        {
        }
        
        public JwtAuthenticationClient(
            HttpClient httpClient, 
            string apiVersion = "v50.0",
            bool callerWillDisposeHttpClient = false,
            bool isProd = true
            )
        {
            
            _httpClient = httpClient ?? throw new ArgumentException("httpClient");
            _disposeHttpClient = !callerWillDisposeHttpClient;
            ApiVersion = apiVersion;
            _isProd = isProd;
        }

        public async Task JwtUnencryptedPrivateKeyAsync(string clientId, string key, string username)
        {
            Validators.ClientIdKeyUserNameValidator(clientId, key, username);
            await JwtUnencryptedPrivateKeyAsync(clientId, key, username, TokenRequestEndpointUrl);
        }

        public async Task JwtPrivateKeyAsync(string clientId, string key, string passphrase, string username)
        {
            Validators.ClientIdKeyPassphraseUserNameValidator(clientId, key, passphrase, username);
            await JwtPrivateKeyAsync(clientId, key, passphrase, username, TokenRequestEndpointUrl);
        }

        public async Task JwtUnencryptedPrivateKeyAsync(string clientId, string key, string username, string tokenEndpoint)
        {
            (Id, InstanceUrl, AccessToken) = await CallTokenEndpoint(
                CreateJwt(
                    clientId, 
                    KeyHelpers.CreatePrivateKeyWrapper(key),
                    username,
                    _isProd ? ProdAudience : TestAudience
                ),
                tokenEndpoint
            );
        }

        public async Task JwtPrivateKeyAsync(string clientId, string key, string passphrase, string username, string tokenEndpoint)
        {
            (Id, InstanceUrl, AccessToken) = await CallTokenEndpoint(
                CreateJwt(
                    clientId, 
                    KeyHelpers.CreatePrivateKeyWrapperWithPassPhrase(key, passphrase),
                    username,
                    _isProd ? ProdAudience : TestAudience
                ),
                tokenEndpoint
            );
        }

        private string CreateJwt(string clientId, PrivateKeyWrapper keyWrapper, string username, string audience) =>
            Jwt.Jwt.CreateJwt(keyWrapper)
                .AddExpiration(DateTime.UtcNow)
                .AddSubject(username)
                .AddAudience(audience)
                .AddConsumerKey(clientId)
                .Build();

        private async Task<AuthToken> CallTokenEndpoint(string jwt, string tokenEndpoint)
        {
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri(tokenEndpoint),
                Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", GrantType),
                    new KeyValuePair<string, string>("assertion", jwt)
                })
            };
            request.Headers.UserAgent.ParseAdd(string.Concat(UserAgent, "/", ApiVersion));

            HttpResponseMessage responseMessage;
            
            try
            {
                responseMessage = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseContentRead);
            }
            catch (Exception exc)
            {
                throw new ForceAuthenticationException(HttpStatusCode.InternalServerError, exc.Message);
            }
            
            if (responseMessage.IsSuccessStatusCode)
            {
                var authToken = JsonConvert
                    .DeserializeObject<AuthToken>(await responseMessage.Content.ReadAsStringAsync());
                return authToken;
            }

            try
            {
                var errorResponse = JsonConvert
                    .DeserializeObject<AuthErrorResponse>(await responseMessage.Content.ReadAsStringAsync());
                throw new ForceAuthenticationException(
                    responseMessage.StatusCode,
                    $"{errorResponse.Error}: {errorResponse.ErrorDescription}"
                );
            }
            catch (Exception exc)
            {
                throw new ForceAuthenticationException(HttpStatusCode.InternalServerError, exc.Message);
            }
        }
        public void Dispose()
        {
            if (_disposeHttpClient)
            {
                _httpClient?.Dispose();
            }
        }
    }
}