using System;
using System.IO;
using System.Text;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Processing;

using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using System.Configuration;

namespace MarekTestConsole
{

    class Program
    {

        public static byte[] Encrypt(byte[] dataIn, KeyParams keyParams = null) //, string passphrase = null)
        {


            //// populate a keyheader
            //KeyHeaderStruct keyHeader = new KeyHeaderStruct(
            //    Engines.RHX,        // cipher engine
            //    192,                // key size in bytes
            //    IVSizes.V128,       // cipher iv size enum
            //    CipherModes.CTR,    // cipher mode enum
            //    PaddingModes.X923,  // cipher padding mode enum
            //    BlockSizes.B128,    // block size enum
            //    RoundCounts.R18,    // diffusion rounds enum
            //    Digests.Skein512,   // cipher kdf engine
            //    64,                 // mac size
            //    Digests.Keccak);    // mac digest

            //// create the key file
            //new KeyFactory(KeyPath).Create(keyHeader);



            ////if (keyParams == null)
            ////{
            ////    using (KeyGenerator kg = new KeyGenerator())
            ////    {
            ////        keyParams = kg.GetKeyParams(192, 64, 64);
            ////    }
            ////}

            //////encryptedData.Key = keyParams.Key;
            //////encryptedData.Iv = keyParams.IV;
            //////encryptedData.Salt = keyParams.IKM;

            // RSM: Rijndael and Serpent merged. HKDF key schedule and up to 42 rounds of diffusion
            using (ICipherMode cipher = new CTR(new RSM(42, 32))) // TSM(32))) //, 32))) // TODO:  42, 32)))  ... for RSM: RSM(18, 32)
            {
                // init with key and iv
                //////cipher.Initialize(true, keyParams);

                /*
                    The Compression cipher wraps the StreamCipher class by first compressing a target directory, then encrypting the compressed file. Decryption inflates the directory to a target path.
                */
                ////using (CompressionCipher cstrm = new CompressionCipher(true, cipher))
                ///


                //////using (CipherStream sc = new CipherStream(cipher))
                //////{
                //////    MemoryStream dataOut = new MemoryStream();
                //////    sc.Initialize(true, keyParams);
                //////    // encrypt the buffer
                //////    sc.Write(new MemoryStream(dataIn), dataOut);
                //////    return dataOut.ToArray();
                //////}



                using (CompressionCipher cstrm = new CompressionCipher(cipher))
                {
                    using (MemoryStream dataInStream = new MemoryStream(dataIn))
                    using (MemoryStream dataOutStream = new MemoryStream())
                    {
                        //////var dataInMemStream = ; // TODO: rollup in Initialize
                        cstrm.Initialize(true, keyParams);
                        cstrm.Write(dataInStream, dataOutStream);
                        return dataOutStream.ToArray();
                    }
                }
            }

            //////return encryptedData;
        }

        //public static string DecryptStream(Stream str, string keyStrBase64)
        //{

        //    byte[] keyBytes = Convert.FromBase64String(keyStrBase64);
        //    string keyStr = Encoding.UTF8.GetString(keyBytes);

        //    Security.Encryption.EncryptedData encryptedData = Security.Encryption.EncryptedData.DeserializeJSON(keyStr);
        //    encryptedData.Content = str.ReadFully();

        //    return Security.Encryption.DecryptToString(encryptedData);
        //}

        public static byte[] Decrypt(byte[] dataIn, KeyParams keyParams) //, string passphrase = null)
        {
            //byte[] decryptedData = null;

            ////KeyParams kp = new KeyParams(keyParams.Key, keyParams.IV, new byte[3] { 1, 2, 3 });

            // RSM: Rijndael and Serpent merged. HKDF key schedule and up to 42 rounds of diffusion
            using (ICipherMode cipher = new CTR(new RSM(42, 32))) // TSM(32))) //, 32))) // TODO: Test TSM! ... for RSM: RSM(18, 32)
            {
                // init with key and iv
                //////cipher.Initialize(false, keyParams);

                //////using (CipherStream sc = new CipherStream(cipher))
                //////{
                //////    MemoryStream dataOut = new MemoryStream();
                //////    sc.Initialize(false, keyParams);
                //////    // encrypt the buffer
                //////    sc.Write(new MemoryStream(dataIn), dataOut);
                //////    return dataOut.ToArray();
                //////}

                //////////using (CompressionCipher cstrm = new CompressionCipher(true, cipher))
                using (CompressionCipher cstrm = new CompressionCipher(cipher))
                {
                    using (MemoryStream dataInStream = new MemoryStream(dataIn))
                    using (MemoryStream dataOutStream = new MemoryStream())
                    {
                        //////var dataInMemStream = ; // TODO: rollup in Initialize
                        cstrm.Initialize(false, keyParams);
                        cstrm.Write(dataInStream, dataOutStream);
                        return dataOutStream.ToArray();
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            KeyParams keyParams = null;

            byte[] test = Encoding.UTF8.GetBytes("ala ma kotka");
            var testStream = new MemoryStream(test);

            using (KeyGenerator kg = new KeyGenerator())
            {
                keyParams = kg.GetKeyParams(192, 32, 32);  //kg.GetKeyParams(192, 16, 16); // for RSM: kg.GetKeyParams(192, 32, 32);
            }


            var testEncrypted = Encrypt(test, keyParams);
            var testDecrypted = Decrypt(testEncrypted, keyParams);

            var xxxxx = Encoding.UTF8.GetString(testDecrypted);

        }
    }
}
