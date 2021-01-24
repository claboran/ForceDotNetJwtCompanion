using System.Text;
using ForceDotNetJwtCompanion.Util;
using Newtonsoft.Json;

namespace ForceDotNetJwtCompanion.Jwt
{
    /// <summary>
    /// 
    /// JwtPayload
    ///
    /// Provides Salesforce JWT info
    /// 
    /// <see>https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm&amp;type=5</see>
    /// 
    /// </summary>
    public class JwtPayload
    {
        [JsonProperty("iss")]
        public string Iss { get; set; }
        [JsonProperty("sub")]
        public string Sub { get; set; }
        [JsonProperty("aud")]
        public string Aud { get; set; }
        [JsonProperty("exp")]
        public string Exp { get; set; }
        public string ConvertToBase64() => CommonHelpers
            .UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(this)));
    }
}