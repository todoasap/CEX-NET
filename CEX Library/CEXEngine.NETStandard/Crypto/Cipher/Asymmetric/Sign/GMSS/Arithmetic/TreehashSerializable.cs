using System;
using System.Collections.Generic;
using System.Text;
using VTDev.Libraries.CEXEngine.Crypto.Digest;

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Arithmetic
{
    public class TreehashSerializable
    {
        // max height of current treehash instance.
        public int _maxHeight { get; set; }
        // Vector element that stores the nodes on the stack
        public List<byte[]> _tailStack { get; set; }
        // Vector element that stores the height of the nodes on the stack
        public List<int> _heightOfNodes { get; set; }
        // the first node is stored in the treehash instance itself, not on stack
        public byte[] _firstNode { get; set; }
        // seedActive needed for the actual node
        public byte[] _seedActive { get; set; }
        // the seed needed for the next re-initialization of the treehash instance
        public byte[] _seedNext { get; set; }
        // number of nodes stored on the stack and belonging to this treehash instance
        public int _tailLength { get; set; }
        // the height in the tree of the first node stored in treehash
        public int _firstNodeHeight { get; set; }
        // true if treehash instance was already initialized, false otherwise
        public bool m_isInitialized { get; set; }
        // true if the first node's height equals the maxHeight of the treehash
        public bool _isFinished { get; set; }
        // true if the nextSeed has been initialized with index 3*2^h needed for the seed scheduling
        public bool _seedInitialized { get; set; }
        //// denotes the Message Digest used by the tree to create nodes
        //public IDigest _msgDigestTree;
        public bool m_isDisposed { get; set; } = false;

        //public Treehash ToTreehash(IDigest Digest)
        //{

        //}
    }
}
