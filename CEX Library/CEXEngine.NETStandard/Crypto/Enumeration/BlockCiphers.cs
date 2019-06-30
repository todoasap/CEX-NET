namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Block Ciphers
    /// </summary>
    public enum BlockCiphers : int
    {
        /// <summary>
        /// No cipher was selected
        /// </summary>
        None = 0,
        /// <summary>
        /// An implementation based on the Rijndael Block Cipher
        /// </summary>
        Rijndael = 1,
        /// <summary>
        /// An implementation based on the Rijndael Block Cipher extended with an HKDF key schedule
        /// </summary>
        RHX = 2,

        /// <summary>
        /// An implementation based on the Serpent Block Cipher
        /// </summary>
        Serpent = 4,
        /// <summary>
        /// An implementation based on the Serpent Block Cipher extended with an HKDF key schedule
        /// </summary>
        SHX = 8,
        /// <summary>
        /// An implementation based on the Twofish Block Cipher
        /// </summary>
        Twofish = 16,
        /// <summary>
        /// An implementation based on the Twofish Block Cipher extended with an HKDF key schedule
        /// </summary>
        THX = 32,

        /// <summary>
        /// An implementation based on the Rijndael and Serpent Merged Block Cipher
        /// </summary>
        RSM = 1003,

        /// <summary>
        /// An implementation based on the Twofish and Serpent Merged Block Ciphers, using an HKDF Key Schedule
        /// </summary>
        TSM = 1004
    }
}
