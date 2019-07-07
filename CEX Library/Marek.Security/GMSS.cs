using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS;

namespace Marek.Security
{
    public class GMSS
    {
        private static GMSSParamSets.GMSSParamNames GMSSVersion = GMSSParamSets.GMSSParamNames.N2P10; //.N2P10SHA512;

        public static Tuple<string, string> GenerateGMSSKeys(string keyFileLabel, string workDirPath = null, bool reuseExistingFiles = true)
        {
            var privKeyFileName = GetPrivateKeyFileNameForLabel(keyFileLabel);
            var pubKeyFileName = GetPublicKeyFileNameForLabel(keyFileLabel);

            if(!String.IsNullOrEmpty(workDirPath))
            {
                privKeyFileName = Path.Combine(workDirPath, privKeyFileName);
                pubKeyFileName = Path.Combine(workDirPath, pubKeyFileName);
            }

            if (!reuseExistingFiles || !File.Exists(privKeyFileName) || !File.Exists(pubKeyFileName))
            {
                GMSSKeyGenerator mkgen = new GMSSKeyGenerator(GMSSParamSets.FromName(GMSSVersion));
                IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();

                var privKeyPem = GetPemStringFromGMSSPrivateKey((GMSSPrivateKey)akp.PrivateKey);
                var pubKeyPem = GetPemStringFromGMSSPublicKey((GMSSPublicKey)akp.PublicKey);

                File.WriteAllText(privKeyFileName, privKeyPem);
                File.WriteAllText(pubKeyFileName, pubKeyPem);
            }

            return new Tuple<string, string>(privKeyFileName, pubKeyFileName);
        }

        public static byte[] SignWithGMSS(byte[] data, string privateKeyFileName)
        {
            var privateKey = GetGMSSPrivateKeyFromPemString(File.ReadAllText(privateKeyFileName));

            using (GMSSSign sgn = new GMSSSign(GMSSParamSets.FromName(GMSSVersion)))
            {
                sgn.Initialize(privateKey);
                var signature = sgn.Sign(new MemoryStream(data));

                // Updating private key with the next one & storing on disk:
                privateKey = privateKey.NextKey();
                // TODO: If catch exception about that no more signatures, then just erase the priv key file or sth
                File.WriteAllText(privateKeyFileName, GetPemStringFromGMSSPrivateKey(privateKey));

                return signature;
            }
        }

        public static bool VerifyGMSSSignature(byte[] data, byte[] signature, string pulicKeyFileName)
        {
            var publicKey = GetGMSSPublicKeyFromPemString(File.ReadAllText(pulicKeyFileName));

            using (GMSSSign sgn = new GMSSSign(GMSSParamSets.FromName(GMSSVersion)))
            {
                sgn.Initialize(publicKey);
                return sgn.Verify(new MemoryStream(data), signature);
            }
        }

        #region Helpers

        public static string GetPrivateKeyFileNameForLabel(string label)
        {
            return label + "_Private.txt";
        }
        public static string GetPublicKeyFileNameForLabel(string label)
        {
            return label + "_Public.txt";
        }

        public static GMSSPrivateKey GetGMSSPrivateKeyFromPemString(string keyPem)
        {
            return GMSSPrivateKey.From(Convert.FromBase64String(keyPem.Replace($"-----BEGIN GMSS.{GMSSVersion} PRIVATE KEY-----{Environment.NewLine}", "").Replace($"-----END GMSS PRIVATE KEY-----{Environment.NewLine}", "")));
        }
        public static string GetPemStringFromGMSSPrivateKey(GMSSPrivateKey key)
        {
            return $"-----BEGIN GMSS.{GMSSVersion} PRIVATE KEY-----{Environment.NewLine}{Convert.ToBase64String(key.ToBytes(), Base64FormattingOptions.InsertLineBreaks)}{Environment.NewLine}-----END GMSS PRIVATE KEY-----{Environment.NewLine}";
        }
        public static GMSSPublicKey GetGMSSPublicKeyFromPemString(string keyPem)
        {
            return GMSSPublicKey.From(Convert.FromBase64String(keyPem.Replace($"-----BEGIN GMSS.{GMSSVersion} PUBLIC KEY-----{Environment.NewLine}", "").Replace($"-----END GMSS PUBLIC KEY-----{Environment.NewLine}", "")));
        }
        public static string GetPemStringFromGMSSPublicKey(GMSSPublicKey key)
        {
            return $"-----BEGIN GMSS.{GMSSVersion} PUBLIC KEY-----{Environment.NewLine}{Convert.ToBase64String(key.ToBytes(), Base64FormattingOptions.InsertLineBreaks)}{Environment.NewLine}-----END GMSS PUBLIC KEY-----{Environment.NewLine}";
        }
        #endregion
    }
}
