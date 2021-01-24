using System;
using System.Threading.Tasks;
using ForceDotNetJwtCompanion;
using ForceDotNetJwtCompanion.Util;
using Xunit;
using Xunit.Abstractions;

namespace ForceDotNetJwtCompanionTest.Tests
{
    public class AuthenticationClientTests : IClassFixture<SfMockAuthServerFixture>
    {
        private readonly SfMockAuthServerFixture _authServerFixture;
        public AuthenticationClientTests(SfMockAuthServerFixture authServerFixture)
        {
            _authServerFixture = authServerFixture;
        }

        [Fact]
        public async Task Authenticate_WithUnencryptedKey_Success()
        {
            var authClient = new JwtAuthenticationClient();
            await authClient.JwtUnencryptedPrivateKeyAsync(
                "jgasgdjasgdajsgdjs", 
                CommonHelpers.LoadFromFile("TestKeys/server.key"), 
                "user", 
                $"http://localhost:{_authServerFixture.PublicPort}/services/oauth2/token"
                );
            Assert.Equal("jhjhdjashdjashdjashdjashdjasdhsjadhasjdhj", authClient.AccessToken);
            Assert.Equal("https://my-org.salesforce.com", authClient.InstanceUrl);
        }
        
        [Fact]
        public async Task Authenticate_WithUnencryptedKey_401Exception()
        {
            var authClient = new JwtAuthenticationClient();
            var assertion = await Assert.ThrowsAsync<ForceAuthenticationException>(async () =>
            {
                await authClient.JwtUnencryptedPrivateKeyAsync(
                    "jgasgdjasgdajsgdjs", 
                    CommonHelpers.LoadFromFile("TestKeys/server.key"), 
                    "user-error", 
                    $"http://localhost:{_authServerFixture.PublicPort}/services/oauth2/token"
                );
            });
                
            Assert.Equal("invalid_grant: an error description", assertion.Message);
        }

        [Fact]
        public async Task Authenticate_WithUnencryptedKey_404Exception()
        {
            var authClient = new JwtAuthenticationClient();
            var assertion = await Assert.ThrowsAsync<ForceAuthenticationException>(async () =>
            {
                await authClient.JwtUnencryptedPrivateKeyAsync(
                    "jgasgdjasgdajsgdjs", 
                    CommonHelpers.LoadFromFile("TestKeys/server.key"), 
                    "user", 
                    $"http://localhost:{_authServerFixture.PublicPort}/servicesx/oauth2/token"
                );
            });
                
            // TODO Somewhat strange error in case of 404, needs further investigation
            Assert.Equal(
                "Unexpected character encountered while parsing value: <. Path '', line 0, position 0.", 
                assertion.Message
                );
        }

    }
}