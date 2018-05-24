using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Numerics;

namespace edatat
{
    public class EDATData
    {
        public long flags;
        public long blockSize;
        public BigInteger fileLen;

        public EDATData()
        {
        }

        public static EDATData createEDATData(byte[] data)
        {
            EDATData result = new EDATData();
            result.flags = ConversionUtils.be32(data, 0);
            result.blockSize = ConversionUtils.be32(data, 4);
            result.fileLen = ConversionUtils.be64(data, 0x8);
            return result;
        }

        public long getBlockSize()
        {
            return blockSize;
        }

        public BigInteger getFileLen()
        {
            return fileLen;
        }

        public long getFlags()
        {
            return flags;
        }
    }
}
