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
                .AddExpiration(new DateTime(2021, 1, 10, 0, 0 ,0, DateTimeKind.Utc))
                .AddSubject("chris@laboranowitsch.de")
                .AddAudience("https://test.salesforce.com")
                .AddConsumerKey("3MVG99OxTyEMCQ3gNp2PjkqeZKxnmAiG1xV4oHh9AKL_rSK.BoSVPGZHQukXnVjzRgSuQqGn75NL7yfkQcyy7")
                .Build();
            
            Assert
                .Equal(
                    "eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiIzTVZHOTlPeFR5RU1DUTNnTnAyUGprcWVaS3hubUFpRzF4VjRvSGg5QUtMX3JTSy5Cb1NWUEdaSFF1a1huVmp6UmdTdVFxR243NU5MN3lma1FjeXk3Iiwic3ViIjoiY2hyaXNAbGFib3Jhbm93aXRzY2guZGUiLCJhdWQiOiJodHRwczovL3Rlc3Quc2FsZXNmb3JjZS5jb20iLCJleHAiOiIxNjEwMjM2OTgwIn0.yFqkMQyIatXBdsGaOnZggFLzDa7Mr-7j7IHel65cOmUIzDOoAPhfqhnZLInBJ36hF96kvMS6Xhd1BYVyzplnA9N0uQU1xpBKi0dAzWTp1miIjNnKcTeMEAoeb3ADhIwZWziTaTiupjjoUSyn_TGkg3m2rpikwdkwgWpaWH-tk648trC49fw0tgI81zePWmorQ42lDXWVpWcnWTUg4aiiG--ObYwgciMtWEFc8g3sW4lJ_7J7i8jY6KBqPuNW6HIq38pi6ScnPCy9Z2vEdiqzzUM9hQK0_aksaY01mhLsNwNTrjTEs7FiC18mNy7Z8dml46dA6ENzfFU9Zf6JyqWAIw",
                    jwt 
                    );
        }
        
    }
}