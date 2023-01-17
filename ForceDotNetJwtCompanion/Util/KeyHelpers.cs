using System;
using System.IO;
using ForceDotNetJwtCompanion.Models;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace ForceDotNetJwtCompanion.Util
{
    /// <summary>
    /// 
    /// KeyHelpers
    /// A set of helper functions to handle Private keys.
    /// 
    /// The implementation is based on BouncyCastle.
    ///
    /// <see>https://www.bouncycastle.org/csharp/index.html</see>
    /// 
    /// </summary>
    public static class KeyHelpers
    {
        /// <summary>
        ///
        /// PrivateKeyWrapper
        /// 
        /// Extracts Modulus and Exponent of a private key.
        /// Support for PEM format (unencrypted).
        /// 
        /// </summary>
        /// <param name="key">Private Key in PEM Format</param>
        /// <returns>PrivateKeyWrapper</returns>
        public static PrivateKeyWrapper CreatePrivateKeyWrapper(string key)
        {
            
            var keyStruct = RsaPrivateKeyStructure
                .GetInstance(
                    (Asn1Sequence)Asn1Object
                    .FromByteArray(Convert
                        .FromBase64String(CommonHelpers.RemoveHeaderFooterFromKey(key)))
                    );

            return new PrivateKeyWrapper
            {
                Modulus = keyStruct.Modulus, 
                Exponent = keyStruct.PrivateExponent
            };
        }

        public static byte[] CreateSignature(PrivateKeyWrapper privateKeyWrapper, byte[] bytesToSign)
        {
            var sig = SignerUtilities.GetSigner("SHA" + 256 + "withRSA");
            sig.Init(
                true, 
                new RsaKeyParameters(
                    true, 
                    privateKeyWrapper.Modulus, 
                    privateKeyWrapper.Exponent
                    )
                );
            sig.BlockUpdate(bytesToSign, 0, bytesToSign.Length);

            return sig.GenerateSignature();
        }

        public static PrivateKeyWrapper CreatePrivateKeyWrapperWithPassPhrase(string key, string passphrase)
        {
            var pemReader = new PemReader(new StringReader(key), new PasswordFinder(passphrase));
            var pem = (AsymmetricCipherKeyPair) pemReader.ReadObject();
            var param = (RsaPrivateCrtKeyParameters) pem.Private;

            return new PrivateKeyWrapper
            {
                Modulus = param.Modulus, 
                Exponent = param.Exponent
            };
        }
    }
}