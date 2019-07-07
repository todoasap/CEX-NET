using System;

namespace Marek.Common
{
    public static class Extensions
    {
        #region Compression
        public static byte[] CompressToGZip(this byte[] data)
        {
            return Compressor.Compress(data, Compressor.Algorithm.GZip);
        }
        public static byte[] DecompressFromGZip(this byte[] data)
        {
            return Compressor.Decompress(data, Compressor.Algorithm.GZip);
        }
        #endregion
    }
}
