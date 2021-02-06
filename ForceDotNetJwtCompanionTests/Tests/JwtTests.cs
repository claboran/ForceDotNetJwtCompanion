using System;
using ForceDotNetJwtCompanion.Jwt;
using ForceDotNetJwtCompanion.Util;
using Xunit;

namespace ForceDotNetJwtCompanionTests.Tests
{
    public class JwtTests
    {

        [Fact]
        public void JwtPayloadToBase64_SimpleInput_Success()
        {
            Assert
                .Equal(
                    "eyJpc3MiOiJramtqa2prIiwic3ViIjoiamhqaGpoIiwiYXVkIjoiamhqaGpoamhqIiwiZXhwIjoibGprbGtsa2xrbCJ9", 
                    new JwtPayload
                    {
                        Aud = "jhjhjhjhj",
                        Exp = "ljklklklkl",
                        Iss = "kjkjkjk",
                        Sub = "jhjhjh"
                    }.ConvertToBase64());
        }
        
        [Fact]
        public void CreateJwt_SimpleInput_Success()
        {
            var jwt = Jwt.CreateJwt(
                    KeyHelpers
                        .CreatePrivateKeyWrapper(CommonHelpers.LoadFromFile("TestKeys/server.key"))
                    )
                .AddExpiration(new DateTime(2021, 1, 10))
                .AddSubject("chris@laboranowitsch.de")
                .AddTokenEndpoint("https://test.salesforce.com")
                .AddConsumerKey("3MVG99OxTyEMCQ3gNp2PjkqeZKxnmAiG1xV4oHh9AKL_rSK.BoSVPGZHQukXnVjzRgSuQqGn75NL7yfkQcyy7")
                .Build();
            
            Assert
                .Equal(
                    "eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiIzTVZHOTlPeFR5RU1DUTNnTnAyUGprcWVaS3hubUFpRzF4VjRvSGg5QUtMX3JTSy5Cb1NWUEdaSFF1a1huVmp6UmdTdVFxR243NU5MN3lma1FjeXk3Iiwic3ViIjoiY2hyaXNAbGFib3Jhbm93aXRzY2guZGUiLCJhdWQiOiJodHRwczovL3Rlc3Quc2FsZXNmb3JjZS5jb20iLCJleHAiOiIxNjEwMjMzMzgwIn0.g94FvtiW3bOR2aLayj7aEtZMmBOB6zzH6Ikd1Xqtvi1s7vywj07JLjzY1avRxdVxQ9SVz434vBn5Wu5mWQWiCO52h0lKM773-_cTUW5rNTBD-wbUXsW97uHG2omxm0gAghcOTdp53P2TDAilvLVnhFJjr_fO8O9jDsyNjgmGQlLNYR_8LCIY0e8N3dmFxhFgnSm1Mbcx9Hd8tLsdAaoiqgi0fyXMjZkRfmSOSnFtorW4nHumWisYPTM9ICdEez9O2VPyQBhy930Mjyt-ZRoQQlDhfysPeebuZo1TRLP25ADzgdm2P0W4xaFFCVhH60r2wiOjemi572KtAqRjDpRyrA",
                    jwt 
                    );
        }
        
    }
}