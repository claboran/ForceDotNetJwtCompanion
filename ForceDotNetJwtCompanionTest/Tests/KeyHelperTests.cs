using ForceDotNetJwtCompanion.Util;
using Xunit;
using static ForceDotNetJwtCompanion.Util.CommonHelpers;

namespace ForceDotNetJwtCompanionTest.Tests
{
    public class KeyHelperTests
    {

        private string GetTestPrivKey() => @"MIIEpAIBAAKCAQEA0vU1360pbcmi9lXFyH3Cm4pqvoN01ni8b07pEzNb8dUbn5/D
B6ubrX5RjZnknGMt3LqgpBbHj1xqbxi4kT/dTViW587wJLVD9nFVVRiwV8rTTie/
teDT8Cb7mQz2ku4Htvd7Vs3IP8J63mlluuv86lcJ6UUhEcBd+1PG3qbrC0ouM42Q
8Ex2NqmsvANQuWtOfJ594MvsdZUtEHkWR4BRG73obgsOZ1RNF7Wfp/xe/FiFGV4d
dqcaujQ9k5mEFwSW+V6d6ihISDU3b9Z17ARAltnrlBYcfr6lkIlT/Z9prPv+j61l
zso1dpoePctRe2WDqZq//m+H7u5O/DANSZbb4QIDAQABAoIBAHRswivM/GVL9/Ut
hzdMOL/w11KHaE8JWS2xBi8DlEXWECW7XT55djR813NnsGSi0+fS099bdw1mupLP
uOToszEBqF8MtTn9FCIJkEejlYcOOCoVA9fT2gPa79Ya8mZKmdVfpiFU9qRBp9/h
mTRdEzsdiCnGbibG3Ndc+A9fXa7fZA6NRd758bQ+y5BTEfOfAaFaHAXQmq+wfG5q
0yd6I9cQHoyBjXDdAN07xnizilFLTXrBfhsK2LBFwdhxdEHpRh00oLQCWMXFAlpf
obxhnI3qNaeWq+0m5YsxQzaUXuwkGysXvouXkPOAXRi91pG6FAencmK4DAJd8j4A
4/vYubUCgYEA8MEG92xbMEyMrevof5wuK/kyZkKml78BDTKMoSdgx7rgrymGqZpC
9aJ3ayUBuArIRmlMo6X967vZve9MjGjqhL7rpYUxQO/YT0voB+ChnBaeSlh/+w9+
6clv7UNimt676TffX/x8tX1yzOhq/QDk/h9HCMJDbDXQrAaUZ5xo6BsCgYEA4FEk
5pBAkaOy7XMz+g4MyoTBNU9dUgzB+WKW9397P+bDjEIsdV/fw1LBSFVa4DZBy5KY
nWfuBJUAzLuSE/0xhSJmeK0xxQR6NVfcpkHGwnx2S1u0Ha89ygvOPQTFReFf46Iz
dy2y28I/ioPWAwPhEqH9+VdganC+paRseSFQw7MCgYBF8r80ad4ApW0GJxFw6g6c
JhXXkivW0N7cV8B2HfvHa+tV2QnQAwrLVT2++oyKTU+s7XEf5t1kfTqhLYKfFOh2
UwYiHBWYWVcOiu5KQ6CQuh2ZWics6W6lPCpx0+81MduEwf/7Yl9VV7JgCHL1OSpP
DwVTbSWrreMH6A18IPx12wKBgQDdMEZRr6Zrtd5mc/WpuZb1T4hwt8yObpQLBCNW
83al4Tero0jRiHNN19lNKRVOB1JDmU8xz1yNWhwKxV5apYzh+bTPhACShEK5POUP
b8a82huPXWKy7qzgAVohIwYfTQfPn45eE0rNlbIwNKWgHYAfbmrQJk+lRX1IOmTX
4HkSLwKBgQCh1c58bSZcugDgDNV6JZrtE9Sicj5hn2pNgtNhIZlugFJxdEhgiJyT
lEJV0RJyWbT3vPrbk3Gq2NCKyiI9MvePloA2oDx7NWe21AgdvP3UmfLBij9IFwsM
F46jxD/IWyLCGcW0/TVeRhK4AhrgohSlwyTXbSoqkFQgmHO/iRjbSw==";
        
        
        [Fact]
        public void RemoveFileHeaderFromKey_SimpleInput_Success()
        {
            var file = LoadFromFile("TestKeys/server.key");
            Assert.Equal(GetTestPrivKey(), RemoveHeaderFooterFromKey(file));
        }
        
        [Fact]
        public void CreatePrivateKeyWrapper_UnencryptedInput_Success()
        {
            var keyWrapper = KeyHelpers
                .CreatePrivateKeyWrapper(LoadFromFile("TestKeys/server.key"));
            Assert.Equal(5691476862716795873, keyWrapper.Modulus.LongValue);
            Assert.Equal(-991353888792069707, keyWrapper.Exponent.LongValue);
            
        }
        
        [Fact]
        public void CreateSignature_SimpleInput_Success()
        {
            var res = KeyHelpers.CreateSignature(
                KeyHelpers
                    .CreatePrivateKeyWrapper(LoadFromFile("TestKeys/server.key")),
                new byte[]{1, 1, 1}
                );
            Assert.Equal(41, res[0]);
        }

        [Fact]
        public void CreatePrivateKeyWrapper_EncryptedInput_Success()
        {
            var keyWrapper = KeyHelpers
                .CreatePrivateKeyWrapperWithPassPhrase(
                    LoadFromFile("TestKeys/server.pass.key"), 
                    "secret"
                    );
            Assert.Equal(5691476862716795873, keyWrapper.Modulus.LongValue);
            Assert.Equal(-991353888792069707, keyWrapper.Exponent.LongValue);
        }
    }
}