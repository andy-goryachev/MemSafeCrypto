package goryachev.memsafecrypto;


/**
 * Utility methods for converting byte arrays into ints and longs, and back again.
 */
public abstract class Pack
{
	public static int littleEndianToInt(byte[] bs, int off)
	{
		int n = bs[off] & 0xff;
		n |= (bs[++off] & 0xff) << 8;
		n |= (bs[++off] & 0xff) << 16;
		n |= bs[++off] << 24;
		return n;
	}

	
	public static void littleEndianToInt(byte[] bs, int bOff, int[] ns, int nOff, int count)
	{
		for(int i = 0; i < count; ++i)
		{
			ns[nOff + i] = littleEndianToInt(bs, bOff);
			bOff += 4;
		}
	}


	public static int[] littleEndianToInt(byte[] bs, int off, int count)
	{
		int[] ns = new int[count];
		for(int i = 0; i < ns.length; ++i)
		{
			ns[i] = littleEndianToInt(bs, off);
			off += 4;
		}
		return ns;
	}

	
	public static byte[] intToLittleEndian(int n)
	{
		byte[] bs = new byte[4];
		intToLittleEndian(n, bs, 0);
		return bs;
	}


	public static void intToLittleEndian(int n, byte[] bs, int off)
	{
		bs[off] = (byte)(n);
		bs[++off] = (byte)(n >>> 8);
		bs[++off] = (byte)(n >>> 16);
		bs[++off] = (byte)(n >>> 24);
	}


	public static void intToLittleEndian(int[] ns, byte[] bs, int off)
	{
		for(int i = 0; i < ns.length; ++i)
		{
			intToLittleEndian(ns[i], bs, off);
			off += 4;
		}
	}

	
	public static long littleEndianToLong(byte[] bs, int off)
	{
		int lo = littleEndianToInt(bs, off);
		int hi = littleEndianToInt(bs, off + 4);
		return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
	}


	public static byte[] longToLittleEndian(long n)
	{
		byte[] bs = new byte[8];
		longToLittleEndian(n, bs, 0);
		return bs;
	}


	public static void longToLittleEndian(long n, byte[] bs, int off)
	{
		intToLittleEndian((int)(n & 0xffffffffL), bs, off);
		intToLittleEndian((int)(n >>> 32), bs, off + 4);
	}
}
