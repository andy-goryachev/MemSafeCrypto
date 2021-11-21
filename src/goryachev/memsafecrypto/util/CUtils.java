// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.util;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.CIntArray;
import goryachev.memsafecrypto.CLongArray;
import java.io.InputStream;
import java.security.SecureRandom;


/**
 * Various Utility Methods.
 */
public final class CUtils
{
	public static byte[] clone(byte[] data)
	{
		return null == data ? null : data.clone();
	}
	
	
	public static CLongArray clone(CLongArray data)
	{
		return null == data ? null : new CLongArray(data);
	}
	
	
	public static CByteArray clone(CByteArray data)
	{
		return null == data ? null : new CByteArray(data);
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
	
	
	public static long littleEndianToLong(CByteArray bs, int off)
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


	public static void arraycopy(long[] src, int srcPos, CLongArray dest, int destPos, int length)
	{
		dest.copy(destPos, src, srcPos, length);
	}
	
	
	public static void arraycopy(CLongArray src, int srcPos, CLongArray dest, int destPos, int length)
	{
		dest.copy(destPos, src, srcPos, length);
	}


	public static void arraycopy(byte[] src, int srcPos, CByteArray dest, int destPos, int length)
	{
		dest.copy(destPos, src, srcPos, length);
	}


	public static void arraycopy(CByteArray src, int srcPos, CByteArray dest, int destPos, int length)
	{
		dest.copy(destPos, src, srcPos, length);
	}
	
	
	public static void readFully(InputStream in, CByteArray out) throws Exception
	{
		int sz = out.length();
		for(int i=0; i<sz; i++)
		{
			int c = in.read();
			if(c < 0)
			{
				throw new Exception("EOF");
			}
			
			out.write(c);
		}
	}
	

	public static void nextBytes(SecureRandom rnd, CByteArray buf)
	{
		// if we leak one byte at a time, would that be ok?
		byte[] b = new byte[1];
		int sz = buf.length();
		
		for(int i=0; i<sz; i++)
		{
			rnd.nextBytes(b);
			buf.write(b);
		}
	}


	public static void arraycopy(CByteArray src, int srcPos, byte[] dst, int dstPos, int len)
	{
		for(int i=0; i<len; i++)
		{
			byte b = src.get(srcPos + i);
			dst[dstPos + i] = b;
		}
	}
}