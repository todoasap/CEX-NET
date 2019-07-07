using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Marek.Security.Jwt
{
    public class JwtPayload
    {
        [JsonProperty(PropertyName = "jti")]
        public string JwtId { get; set; }

        [JsonProperty(PropertyName = "iss")]
        public string Issuer { get; set; }

        [JsonProperty(PropertyName = "iat")]
        public long IssuedAt { get; set; }

        [JsonProperty(PropertyName = "nbf")]
        public long NotBefore { get; set; }

        [JsonProperty(PropertyName = "exp")]
        public long Expires { get; set; }

        [JsonProperty(PropertyName = "aud")]
        public string Audience { get; set; }

        [JsonProperty(PropertyName = "sub")]
        public string Subject { get; set; }

        public enum ValidationResult // TODO
        {
            TokenOk = 1,
            TokenNotOk = 2
        }

        public string Validate(bool verifyTime, string validIssuer, string validAudience)
        {
            var verifiedPayload = this;
            //JwtTplPayload verifiedPayload = JsonConvert.DeserializeObject<JwtTplPayload>(verifiedPayloadStr);

            #region Time check
            if (verifyTime)
            {
                long nowTs = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (verifiedPayload.NotBefore > nowTs || (verifiedPayload.Expires > 0 && verifiedPayload.Expires < nowTs))
                    return $"Token is invalid at this time ({nowTs}).";
            }
            #endregion

            #region Issuer/Audience verification
            var jwtValidIssConfig = validIssuer;
            if (!String.IsNullOrEmpty(jwtValidIssConfig))
            {
                if (verifiedPayload.Issuer?.Trim().ToLower() != jwtValidIssConfig.Trim().ToLower())
                    return $"Invalid token issuer (expected: {jwtValidIssConfig}).";
            }
            var jwtValidAudConfig = validAudience;
            if (!String.IsNullOrEmpty(jwtValidAudConfig))
            {

                #region Set up  Audience
                List<string> verifiedAudience = null;

                if (verifiedPayload.Audience != null && verifiedPayload.Audience is JArray)
                    verifiedAudience = (List<string>)(((JArray)verifiedPayload.Audience).Select(jv => (String)jv).ToList());
                else if (verifiedPayload.Audience is String)
                    verifiedAudience = new List<string>() { (String)verifiedPayload.Audience };

                #endregion

                if (
                    verifiedAudience == null
                    || !verifiedAudience.Any(aud => aud.Trim().ToLower() == jwtValidAudConfig.Trim().ToLower())
                )
                    return $"Invalid token audience (expected: {jwtValidAudConfig}).";
            }

            #endregion

            //////#region Set up Scope
            //////AuthorizedScopes = null; // = verifiedPayload.Scope;
            //////if (verifiedPayload.Scope != null && verifiedPayload.Scope is JArray)
            //////    AuthorizedScopes = (List<string>)(((JArray)verifiedPayload.Scope).Select(jv => (String)jv).ToList());
            //////else if (verifiedPayload.Scope is String)
            //////    AuthorizedScopes = new List<string>() { (String)verifiedPayload.Scope };
            //////#endregion
            ///
            return "OK";
        }
    }
}
