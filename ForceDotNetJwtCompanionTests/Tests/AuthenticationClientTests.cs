using System.Threading.Tasks;
using ForceDotNetJwtCompanion;
using ForceDotNetJwtCompanion.Util;
using Xunit;

namespace ForceDotNetJwtCompanionTests.Tests
{
    public class AuthenticationClientTests : IClassFixture<SfMockAuthServerFixture>
    {
        private readonly SfMockAuthServerFixture _authServerFixture;

        private const string FakeClientId = "jgasgdjasgdajsgdjs";
        private const string ServerKeyFilePath = "TestKeys/server.key";
        private readonly string _tokenUrl;

        public AuthenticationClientTests(SfMockAuthServerFixture authServerFixture)
        {
            _authServerFixture = authServerFixture;
            _tokenUrl = $"http://localhost:{_authServerFixture.PublicPort}/services/oauth2/token";
        }

        [Fact]
        public async Task Authenticate_WithUnencryptedKey_Success()
        {
            var authClient = new JwtAuthenticationClient();
            await authClient.JwtUnencryptedPrivateKeyAsync(
                FakeClientId,
                CommonHelpers.LoadFromFile(ServerKeyFilePath),
                "user",
                _tokenUrl
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
                    FakeClientId,
                    CommonHelpers.LoadFromFile(ServerKeyFilePath),
                    "user-error",
                    _tokenUrl
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
                    FakeClientId,
                    CommonHelpers.LoadFromFile(ServerKeyFilePath),
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