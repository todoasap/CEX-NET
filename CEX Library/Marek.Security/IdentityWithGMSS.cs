using Marek.Security.Jwt;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Marek.Security
{
    public class IdentityWithGMSS : IDisposable
    {
        private string _thisLabel;
        private string _workDirPath;
        private Tuple<string, string> _keyPairFiles;
        private bool _deleteFilesAfter;

        public IdentityWithGMSS(string label, string workDirPath = null, bool deleteFilesAfterwards = true)
        {
            _thisLabel = label;
            _workDirPath = workDirPath;
            _keyPairFiles = GMSS.GenerateGMSSKeys(_thisLabel, workDirPath);
            _deleteFilesAfter = deleteFilesAfterwards;
        }
        public byte[] GenerateTestIdentityPacket(string audience, int validSeconds)
        {
            JwtPayload jwtPayload = new JwtPayload();
            jwtPayload.Issuer = _thisLabel;
            jwtPayload.IssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            jwtPayload.NotBefore = jwtPayload.IssuedAt;
            jwtPayload.Expires = jwtPayload.NotBefore + validSeconds;
            jwtPayload.Subject = _thisLabel + $"-Delegate{Guid.NewGuid()}";
            jwtPayload.Audience = audience;
            var jwtEncoded = JsonWebToken.Encode(jwtPayload, _keyPairFiles.Item1, JwtAlgorithm.GMSS512);
            return Encoding.UTF8.GetBytes(jwtEncoded);
        }

        public bool VerifyTestIdentityPacket(byte[] identityPacket, string trustedLabel)
        {
            try
            {
                var demoTestTrustedLabelPublicKeyPath = Path.Combine(_workDirPath, GMSS.GetPublicKeyFileNameForLabel(trustedLabel));
                var jwtDecoded = JsonWebToken.Decode(Encoding.UTF8.GetString(identityPacket), demoTestTrustedLabelPublicKeyPath, trustedLabel, _thisLabel);
                return true;
            }
            catch(Exception ex)
            {
                return false;
            }
        }

        public void Dispose()
        {
            if(_deleteFilesAfter)
            {
                File.Delete(_keyPairFiles.Item1);
                File.Delete(_keyPairFiles.Item2);
            }
        }
    }
}
