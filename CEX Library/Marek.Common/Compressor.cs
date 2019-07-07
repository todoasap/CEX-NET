using System;
using System.IO;
using System.IO.Compression;

namespace Marek.Common
{
    public class Compressor
    {
        public enum Algorithm
        {
            GZip
        }
        //private static byte[] ReadFully(Stream input) // TODO: Move to more general Helper
        //{
        //    byte[] buffer = new byte[16 * 1024];
        //    using (MemoryStream ms = new MemoryStream())
        //    {
        //        int read;
        //        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        //        {
        //            ms.Write(buffer, 0, read);
        //        }
        //        return ms.ToArray();
        //    }
        //}
        private static byte[] GZipProcess(byte[] data, CompressionMode mode, Algorithm algorithm)
        {
            using (MemoryStream srcStream = new MemoryStream(data))
            using (MemoryStream dstStream = new MemoryStream())
            {
                using (GZipStream compressionStream = new GZipStream((mode == CompressionMode.Compress ? dstStream : srcStream), mode))
                {
                    (mode == CompressionMode.Compress ? (Stream)srcStream : compressionStream).CopyTo((mode == CompressionMode.Compress ? (Stream)compressionStream : dstStream));
                }
                // MUST be done AFTER disposing GZipStream!!!:
                return dstStream.ToArray();
            }
        }
        public static byte[] Compress(byte[] data, Algorithm algorithm = Algorithm.GZip)
        {
            return GZipProcess(data, CompressionMode.Compress, algorithm);
        }

        public static byte[] Decompress(byte[] dataCompressed, Algorithm algorithm = Algorithm.GZip)
        {
            return GZipProcess(dataCompressed, CompressionMode.Decompress, algorithm);
        }
    }
}
