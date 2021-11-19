// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.bc;

import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.CIntArray;

/**
 * Utility methods.
 */
public final class Utils
{
	public static byte[] clone(byte[] data)
	{
		return null == data ? null : data.clone();
	}


	public static long[] clone(long[] data)
	{
		return null == data ? null : data.clone();
	}
	
	
	public static byte[] toByteArray(String string)
	{
		byte[] bytes = new byte[string.length()];

		for(int i = 0; i != bytes.length; i++)
		{
			char ch = string.charAt(i);

			bytes[i] = (byte)ch;
		}

		return bytes;
	}
	
	
	public static int littleEndianToInt(byte[] bs, int off)
	{
		int n = bs[off] & 0xff;
		n |= (bs[++off] & 0xff) << 8;
		n |= (bs[++off] & 0xff) << 16;
		n |= bs[++off] << 24;
		return n;
	}
	
	
	public static int littleEndianToInt(CByteArray b, int off)
	{
		int n = b.get(off) & 0xff;
		n |= (b.get(++off) & 0xff) << 8;
		n |= (b.get(++off) & 0xff) << 16;
		n |= b.get(++off) << 24;
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
	
	
	public static void littleEndianToInt(CByteArray bs, int bOff, CIntArray ns, int nOff, int count)
	{
		for(int i = 0; i < count; ++i)
		{
			ns.set(nOff + i, littleEndianToInt(bs, bOff));
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


	public static void intToLittleEndian(int n, byte[] bs, int off)
	{
		bs[off] = (byte)(n);
		bs[++off] = (byte)(n >>> 8);
		bs[++off] = (byte)(n >>> 16);
		bs[++off] = (byte)(n >>> 24);
	}
	
	
	public static void intToLittleEndian(int n, CByteArray bs, int off)
	{
		bs.set(off, (byte)(n));
		bs.set(++off, (byte)(n >>> 8));
		bs.set(++off, (byte)(n >>> 16));
		bs.set(++off, (byte)(n >>> 24));
	}


	public static void intToLittleEndian(int[] ns, byte[] bs, int off)
	{
		for(int i = 0; i < ns.length; ++i)
		{
			intToLittleEndian(ns[i], bs, off);
			off += 4;
		}
	}
	
	
	public static void intToLittleEndian(CIntArray ns, CByteArray b, int off)
	{
		for(int i = 0; i < ns.length(); ++i)
		{
			intToLittleEndian(ns.get(i), b, off);
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
