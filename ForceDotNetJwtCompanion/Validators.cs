using System;

namespace ForceDotNetJwtCompanion
{
    public static class Validators
    {
        private const string Missing = "missing";
        private const string SecretPlaceholder = "...";
        
        public static void ClientIdKeyUserNameValidator(string clientId, string key, string username)
        {
            if (
                string.IsNullOrEmpty(clientId) ||
                string.IsNullOrEmpty(key) ||
                string.IsNullOrEmpty(username)
            ) throw new ArgumentException(
                $"Missing arguments -> clientId: {clientId ?? Missing}, " + 
                        $"key: {(string.IsNullOrEmpty(key) ? Missing : SecretPlaceholder)}, " +
                        $"username: {username ?? Missing}"
                );
        }
        
        public static void ClientIdKeyPassphraseUserNameValidator(
            string clientId, 
            string key, 
            string passphrase, 
            string username)
        {
            if (
                string.IsNullOrEmpty(clientId) ||
                string.IsNullOrEmpty(key) ||
                string.IsNullOrEmpty(passphrase) ||
                string.IsNullOrEmpty(username)
            ) throw new ArgumentException(
                $"Missing arguments -> clientId: {clientId ?? Missing}, " + 
                $"key: {(string.IsNullOrEmpty(key) ? Missing : SecretPlaceholder)}, " +
                $"passphrase: {(string.IsNullOrEmpty(passphrase) ? Missing : SecretPlaceholder)}, " +
                $"username: {username ?? Missing}"
            );
        }

    }
}