using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Marek.Security.Jwt
{
    // JWT

    public enum JwtAlgorithm
    {
        //RS256,
        HS256,
        HS384,
        HS512,

        // ECC:
        ////ES512
        GMSS512 //,
        //GMSS512
    }
    // See: https://stackoverflow.com/questions/10055158/is-there-a-json-web-token-jwt-example-in-c
    public class JsonWebToken
    {
        private static Dictionary<JwtAlgorithm, Func<string, byte[], byte[]>> HashComputeAlgorithms;
        private static Dictionary<JwtAlgorithm, Func<string, byte[], byte[], bool>> HashVerifyAsymmAlgorithms;

        static JsonWebToken()
        {
            HashComputeAlgorithms = new Dictionary<JwtAlgorithm, Func<string, byte[], byte[]>>
            {
                //{ JwtHashAlgorithm.RS256, (key, value) => { using (var sha = new HMACSHA256(key)) { return sha.ComputeHash(value); } } }, // ???????
                { JwtAlgorithm.HS256, (key, value) => { using (var sha = new HMACSHA256(Convert.FromBase64String((string)key))) { return sha.ComputeHash(value); } } }, // ???????
                { JwtAlgorithm.HS384, (key, value) => { using (var sha = new HMACSHA384(Convert.FromBase64String((string)key))) { return sha.ComputeHash(value); } } },
                { JwtAlgorithm.HS512, (key, value) => { using (var sha = new HMACSHA512(Convert.FromBase64String((string)key))) { return sha.ComputeHash(value); } } },
                { JwtAlgorithm.GMSS512, (gmssPrivKey, value) => { using (var gmss = new GMSSSHA512(gmssPrivKey, null)) { return gmss.ComputeHash(value); } } }
            };
            HashVerifyAsymmAlgorithms = new Dictionary<JwtAlgorithm, Func<string, byte[], byte[], bool>>
            {
                { JwtAlgorithm.GMSS512, (gmssPubKey, value, signature) => { using (var gmss = new GMSSSHA512(null, gmssPubKey)) { return gmss.VerifyDataSignature(value, signature); } } }
            };
        }

        //public static string Encode(object payload, string key, JwtAlgorithm algorithm)
        //{
        //    return Encode(payload, key, algorithm);
        //}

        public static string Encode(object payload, string key, JwtAlgorithm algorithm, string headerAlgCus = null, string headerKeyId = null)
        {
            var segments = new List<string>();
            //var header = new { alg = algorithm.ToString(), typ = "JWT" };

            JsonSerializerSettings jsonSerializerSettings = new JsonSerializerSettings()
            {
                Formatting = Formatting.None,
                NullValueHandling = NullValueHandling.Ignore
            };

            byte[] headerBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new { typ = "JWT", kid = headerKeyId, alg = algorithm.ToString(), cus = headerAlgCus }, jsonSerializerSettings));

            byte[] payloadBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload, jsonSerializerSettings));
            //byte[] payloadBytes = Encoding.UTF8.GetBytes(@"{"iss":"761326798069-r5mljlln1rd4lrbhg75efgigp36m78j5@developer.gserviceaccount.com","scope":"https://www.googleapis.com/auth/prediction","aud":"https://accounts.google.com/o/oauth2/token","exp":1328554385,"iat":1328550785}");

            segments.Add(Base64UrlEncode(headerBytes));
            segments.Add(Base64UrlEncode(payloadBytes));

            var stringToSign = string.Join(".", segments.ToArray());

            var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

            byte[] signature = null;

            signature = HashComputeAlgorithms[algorithm](key, bytesToSign);

            segments.Add(Base64UrlEncode(signature));

            return string.Join(".", segments.ToArray());
        }

        public static JwtPayload Decode(string token, string key, string validIssuer, string validAudience)
        {
            var payload = JsonConvert.DeserializeObject<JwtPayload>( Decode(token, key, true));
            var validationResult = payload.Validate(true, validIssuer, validAudience);
            if (validationResult != "OK")
                throw new Exception($"Invalid token: {validationResult}");
            return payload;
        }

        private static string Decode(string token, string key, bool verify)
        {
            var parts = token.Split('.');
            var header = parts[0];
            var payload = parts[1];
            byte[] crypto = Base64UrlDecode(parts[2]);

            var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(header));
            var headerData = JObject.Parse(headerJson);
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
            var payloadData = JObject.Parse(payloadJson);

            if (verify)
            {
                var bytesToSign = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));
                //var keyBytes = Encoding.UTF8.GetBytes(key);
                var algorithm = (string)headerData["alg"];

                var hashAlgo = GetHashAlgorithm(algorithm);

                if (hashAlgo == JwtAlgorithm.GMSS512)
                {
                    bool verified = HashVerifyAsymmAlgorithms[hashAlgo](key, bytesToSign, crypto);
                    if (!verified)
                        throw new ApplicationException("Invalid GMSS signature");
                }
                else
                {
                    var signature = HashComputeAlgorithms[hashAlgo](key, bytesToSign);
                    var decodedCrypto = Convert.ToBase64String(crypto);
                    var decodedSignature = Convert.ToBase64String(signature);

                    if (decodedCrypto != decodedSignature)
                    {
                        throw new ApplicationException(string.Format("Invalid signature. Expected {0} got {1}", decodedCrypto, decodedSignature));
                    }
                }
            }

            return payloadData.ToString();
        }

        private static JwtAlgorithm GetHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                //case "RS256": return JwtHashAlgorithm.RS256;
                case "HS256": return JwtAlgorithm.HS256;
                case "HS384": return JwtAlgorithm.HS384;
                case "HS512": return JwtAlgorithm.HS512;
                case "GMSS512": return JwtAlgorithm.GMSS512;
                default: throw new InvalidOperationException("Algorithm not supported.");
            }
        }

        // from JWT spec
        private static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        // from JWT spec
        private static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break; // One pad char
                default: throw new System.Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }
    }
}
