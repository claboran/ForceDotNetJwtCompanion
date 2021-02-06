using System;
using Xunit;
using static ForceDotNetJwtCompanion.Validators;

namespace ForceDotNetJwtCompanionTests.Tests
{
    public class ValidatorsTests
    {
        [Fact]
        public void ClientIdKeyUserNameValidator_InputComplete_ThrowNoException()
        {
            ClientIdKeyUserNameValidator("123", "123", "456");
        }
        
        [Fact]
        public void ClientIdKeyUserNameValidator_InputNoClientAndKey_ThrowsException()
        {
            var assertion = Assert.Throws<ArgumentException>(
                () => ClientIdKeyUserNameValidator(null, "", "456")
                );
            Assert.Equal(
                "Missing arguments -> clientId: missing, key: missing, username: 456",
                assertion.Message
            );
            
        }

        [Fact]
        public void ClientIdKeyPassphraseUserNameValidator_InputComplete_ThrowNoException()
        {
            ClientIdKeyPassphraseUserNameValidator("123", "123", "123", "456");
        }
        
        [Fact]
        public void ClientIdKeyPassphraseUserNameValidator_InputNoClientAndKey_ThrowsException()
        {
            var assertion = Assert.Throws<ArgumentException>(
                () => ClientIdKeyPassphraseUserNameValidator(null, "", null, "456")
            );
            Assert.Equal(
                "Missing arguments -> clientId: missing, key: missing, passphrase: missing, username: 456",
                assertion.Message
            );
            
        }
    }
}