using Newtonsoft.Json;

namespace ForceDotNetJwtCompanion.Models
{
    public class AuthToken
    {
        [JsonProperty(PropertyName = "id")]
        public string Id;

        [JsonProperty(PropertyName = "issued_at")]
        public string IssuedAt;

        [JsonProperty(PropertyName = "instance_url")]
        public string InstanceUrl;

        [JsonProperty(PropertyName = "signature")]
        public string Signature;

        [JsonProperty(PropertyName = "access_token")]
        public string AccessToken;

        public void Deconstruct(out string id, out string instanceUrl, out string accessToken)
        {
            id = Id;
            instanceUrl = InstanceUrl;
            accessToken = AccessToken;
        }
    }
}