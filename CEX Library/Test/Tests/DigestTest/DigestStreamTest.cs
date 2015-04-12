﻿#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Crypto.Process;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.DigestTest
{
    /// <summary>
    /// Compares the normal mode of CipherStream with the Concurrent mode for equality
    /// </summary>
    public class DigestStreamTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Compares the normal mode of CipherStream with the Concurrent mode for equality.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All CipherStream tests have executed succesfully.";
        #endregion

        #region Events
        public event EventHandler<TestEventArgs> Progress;
        protected virtual void OnProgress(TestEventArgs e)
        {
            var handler = Progress;
            if (handler != null) handler(this, e);
        }
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>
        /// Tests for correctness of parallel processing mode in the CipherStream implementation
        /// by comparing digest output between both modes performed on random temp files
        /// </summary>
        /// 
        /// <returns>Status</returns>
        public string Test()
        {
            try
            {
                DigestTests();

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Tests
        private string CreateTempFile(int Size)
        {
            string path = Path.GetTempFileName();
            byte[] data = new CSPRng().GetBytes(Size);

            File.WriteAllBytes(path, data);

            return path;
        }

        private void DigestTests()
        {
            string path = CreateTempFile(337983);

            byte[] x1 = HashTest1(path);
            byte[] y1 = HashTest2(path);

            if (File.Exists(path))
                File.Delete(path);

            if ((Compare.AreEqual(x1, y1) == false))
                throw new Exception("Failed! Digest outputs are not equal");

            OnProgress(new TestEventArgs("Passed round 1 comparisons.."));

            path = CreateTempFile(72621);
            x1 = HashTest1(path);
            y1 = HashTest2(path);

            if (File.Exists(path))
                File.Delete(path);

            if ((Compare.AreEqual(x1, y1) == false))
                throw new Exception("Failed! Digest outputs are not equal");

            OnProgress(new TestEventArgs("Passed round 2 comparisons.."));

            path = CreateTempFile(65536);
            x1 = HashTest1(path);
            y1 = HashTest2(path);

            if (File.Exists(path))
                File.Delete(path);

            if ((Compare.AreEqual(x1, y1) == false))
                throw new Exception("Failed! Digest outputs are not equal");

            OnProgress(new TestEventArgs("Passed round 3 comparisons.."));

            if (!HashTest3())
                throw new Exception("Failed! Digest outputs are not equal");

            OnProgress(new TestEventArgs("Passed round 4 comparisons.."));
        }

        private byte[] HashTest1(string FileName)
        {
            using (FileStream inStream = new FileStream(FileName, FileMode.Open))
            {
                using (DigestStream dgst = new DigestStream(new SHA512()))
                {
                    dgst.Initialize(inStream);
                    // run concurrent mode
                    dgst.IsConcurrent = true;
                    return dgst.ComputeHash();
                }
            }
        }

        private byte[] HashTest2(string FileName)
        {
            using (FileStream inStream = new FileStream(FileName, FileMode.Open))
            {
                using (DigestStream dgst = new DigestStream(new SHA512()))
                {
                    dgst.Initialize(inStream);
                    // linear processing
                    dgst.IsConcurrent = false;
                    return dgst.ComputeHash();
                }
            }
        }

        private bool HashTest3()
        {
            byte[] data = new CSPRng().GetBytes(33033);
            byte[] hash1;
            byte[] hash2;

            using (DigestStream dgt1 = new DigestStream(new SHA512()))
            {
                dgt1.Initialize(new MemoryStream(data));
                // run concurrent mode
                dgt1.IsConcurrent = true;
                hash1 = dgt1.ComputeHash();
            }

            using (SHA512 dgt2 = new SHA512())
                hash2 = dgt2.ComputeHash(data);

            return Compare.AreEqual(hash1, hash2);
        }
        #endregion
    }
}
