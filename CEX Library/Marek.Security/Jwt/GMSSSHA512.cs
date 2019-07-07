using Marek.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS;

namespace Marek.Security.Jwt
{
    public class GMSSSHA512 : IDisposable
    {
        private string _privateKeyFile;
        private string _publicKeyFile;
        public GMSSSHA512(string privKeyPemFile, string pubKeyPemFile)
        {
            _privateKeyFile = privKeyPemFile;
            _publicKeyFile = pubKeyPemFile;
        }
        public byte[] ComputeHash(byte[] buffer)
        {
            using (SHA512Managed sha = new SHA512Managed())
            {
                var buffHash = sha.ComputeHash(buffer);
                return GMSS.SignWithGMSS(buffHash, _privateKeyFile);
            }
        }
        public bool VerifyDataSignature(byte[] buffer, byte[] signature)
        {
            using (SHA512Managed sha = new SHA512Managed())
            {
                var buffHash = sha.ComputeHash(buffer);
                return GMSS.VerifyGMSSSignature(buffHash, signature, _publicKeyFile);
            }
        }

        public void Dispose()
        {

        }
    }
}
