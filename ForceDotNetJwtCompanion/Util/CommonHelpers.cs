using System;
using System.Linq;
using static System.IO.File;

namespace ForceDotNetJwtCompanion.Util
{
    public static class CommonHelpers
    {
        private static readonly string[] itemsToRemove =
        {
            "-----BEGIN PRIVATE KEY-----", 
            "-----END PRIVATE KEY-----", 
            "-----BEGIN RSA PRIVATE KEY-----", 
            "-----END RSA PRIVATE KEY-----", 
            "-----BEGIN PUBLIC KEY-----", 
            "-----END PUBLIC KEY-----"
        };

        public static string UrlEncode(byte[] input) => 
            Convert.ToBase64String(input)
                .Split('=')[0]
                .Replace('+', '-')
                .Replace('/', '_');
        
        public static string LoadFromFile(string path) => ReadAllText(path);

        public static string RemoveHeaderFooterFromKey(string key) =>
            itemsToRemove
                .Aggregate(key, 
                    (current, item) => current
                        .Replace(item, string.Empty)
                ).Trim();
    }
}