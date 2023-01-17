using System;
using System.Text;
using ForceDotNetJwtCompanion.Models;
using ForceDotNetJwtCompanion.Util;

namespace ForceDotNetJwtCompanion.Jwt
{
    /// <summary>
    /// Jwt
    /// Main class responsible for Salesforce JWT creation
    ///
    /// It is basically a port of the Java example provided by Salesforce.
    /// Retrieving Modulus and Exponent from key files has been extracted to
    /// helper functions.
    /// 
    /// <see>https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm&type=5</see>
    /// 
    /// </summary>
    public class Jwt
    {
        // Salesforce supports RS256 (no other algorithms are provided so far)
        private const string Header = "{\"alg\": \"RS256\"}";
        private JwtPayload _jwtPayload;
        private string _consumerKey; // aka ClientId
        private string _audience;
        private string _subject; // Salesforce user
        private string _expiration;
        private readonly PrivateKeyWrapper _privateKeyWrapper;

        private Jwt(PrivateKeyWrapper privateKeyWrapper)
        {
            _privateKeyWrapper = privateKeyWrapper;
        }

        public static Jwt CreateJwt(PrivateKeyWrapper privateKeyWrapper) => new(privateKeyWrapper);

        public Jwt AddConsumerKey(string consumerKey)
        {
            _consumerKey = consumerKey;
            return this;
        }

        public Jwt AddAudience(string tokenEndpoint)
        {
            _audience = tokenEndpoint;
            return this;
        }

        public Jwt AddSubject(string subject)
        {
            _subject = subject;
            return this;
        }

        public Jwt AddExpiration(DateTime now)
        { 
            _expiration = JwtHelpers.CreateExpTimeAsString(now);
            return this;
        }

        public string Build()
        {
            if (
                string.IsNullOrEmpty(_consumerKey) ||
                string.IsNullOrEmpty(_expiration) ||
                string.IsNullOrEmpty(_subject) ||
                string.IsNullOrEmpty(_audience) 
                ) throw new ArgumentException("Missing arguments for JWT!");
            
            _jwtPayload = new JwtPayload
            {
                Aud = _audience,
                Exp = _expiration,
                Iss = _consumerKey,
                Sub = _subject
            };

            var bytesToSign = Encoding.UTF8.GetBytes(
                string.Join(".", 
                    CommonHelpers.UrlEncode(Encoding.UTF8.GetBytes(Header)), 
                    _jwtPayload.ConvertToBase64())
                );

            return string
                .Join(".", 
                    CommonHelpers.UrlEncode(Encoding.UTF8.GetBytes(Header)), 
                    _jwtPayload.ConvertToBase64(),
                    CommonHelpers.UrlEncode(KeyHelpers.CreateSignature(_privateKeyWrapper, bytesToSign))
                    );
        }
    }
}