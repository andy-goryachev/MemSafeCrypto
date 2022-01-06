// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.util;
import goryachev.common.util.CKit;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.CCharArray;
import goryachev.memsafecrypto.CIntArray;
import goryachev.memsafecrypto.CLongArray;
import goryachev.memsafecrypto.OpaqueChars;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
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


	/** do not use for secrets! */
	public static byte[] toByteArray(String string)
	{
		byte[] bytes = new byte[string.length()];
		for(int i=0; i<bytes.length; i++)
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
		for(int i=0; i<count; ++i)
		{
			ns[nOff + i] = littleEndianToInt(bs, bOff);
			bOff += 4;
		}
	}
	
	
	public static void littleEndianToInt(CByteArray bs, int bOff, CIntArray ns, int nOff, int count)
	{
		for(int i=0; i<count; ++i)
		{
			ns.set(nOff + i, littleEndianToInt(bs, bOff));
			bOff += 4;
		}
	}
	
	
	public static int[] littleEndianToInt(byte[] bs, int off, int count)
	{
		int[] ns = new int[count];
		for(int i=0; i<ns.length; ++i)
		{
			ns[i] = littleEndianToInt(bs, off);
			off += 4;
		}
		return ns;
	}


	public static void littleEndianToInt(CByteArray bs, int off, CIntArray ns)
	{
    	for(int i=0; i<ns.length(); ++i)
		{
			ns.set(i, littleEndianToInt(bs, off));
			off += 4;
		}
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
		for(int i=0; i<ns.length; ++i)
		{
			intToLittleEndian(ns[i], bs, off);
			off += 4;
		}
	}
	
	
	public static void intToLittleEndian(CIntArray ns, CByteArray b, int off)
	{
		for(int i=0; i<ns.length(); ++i)
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
		dest.copyFrom(src, srcPos, length, destPos);
	}


	public static void arraycopy(CByteArray src, int srcPos, CByteArray dest, int destPos, int length)
	{
		dest.copyFrom(src, srcPos, length, destPos);
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
	
	
	public static void arraycopy(CIntArray src, int srcPos, CIntArray dst, int dstPos, int len)
	{
		for(int i=0; i<len; i++)
		{
			int b = src.get(srcPos + i);
			dst.set(dstPos + i, b);
		}
	}
	
	
    public static void intToBigEndian(int n, byte[] bs, int off)
    {
        bs[off] = (byte)(n >>> 24);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 8);
        bs[++off] = (byte)(n);
    }
	
	
	public static void intToBigEndian(int n, CByteArray bs, int off)
	{
	    bs.set(off, (byte)(n >>> 24));
	    bs.set(++off, (byte)(n >>> 16));
	    bs.set(++off, (byte)(n >>> 8));
	    bs.set(++off, (byte)(n));
	}
	
	
    public static int bigEndianToInt(CByteArray bs, int off)
    {
        int n = bs.get(off) << 24;
        n |= (bs.get(++off) & 0xff) << 16;
        n |= (bs.get(++off) & 0xff) << 8;
        n |= (bs.get(++off) & 0xff);
        return n;
    }
    
    
    public static long bigEndianToLong(CByteArray bs, int off)
    {
        int hi = bigEndianToInt(bs, off);
        int lo = bigEndianToInt(bs, off + 4);
        return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
    }
    
    
    public static void longToBigEndian(long n, CByteArray bs, int off)
    {
        intToBigEndian((int)(n >>> 32), bs, off);
        intToBigEndian((int)(n & 0xffffffffL), bs, off + 4);
	}


	public static void intToLittleEndian(int[] ns, CByteArray bs, int off)
	{
		for(int i=0; i<ns.length; ++i)
		{
			intToLittleEndian(ns[i], bs, off);
			off += 4;
		}
	}


	public static void littleEndianToLong(CByteArray bs, int off, CLongArray ns)
	{
		for(int i=0; i<ns.length(); ++i)
		{
			ns.set(i, littleEndianToLong(bs, off));
			off += 8;
		}
	}


	public static void longToLittleEndian(CLongArray ns, CByteArray bs, int off)
	{
		for(int i=0; i<ns.length(); ++i)
		{
			longToLittleEndian(ns.get(i), bs, off);
			off += 8;
		}
	}


	public static void longToLittleEndian(long n, CByteArray bs, int off)
	{
		intToLittleEndian((int)(n & 0xffffffffL), bs, off);
		intToLittleEndian((int)(n >>> 32), bs, off + 4);
	}
	

	public static CByteArray toUTF8ByteArray(CCharArray text)
	{
		// *4 worst case scenario
		CByteArray b = new CByteArray(text.length() * 4);

		try
		{
			toUTF8ByteArray(text, b);
			
			int len = b.position();
			return b.toReadOnly(0, len);
		}
		catch(IOException e)
		{
			throw new IllegalStateException("cannot encode string to byte array!");
		}
		finally
		{
			b.zero();
		}
	}


	private static void toUTF8ByteArray(CCharArray string, CByteArray sOut) throws IOException
	{
		CCharArray c = string;
		int i = 0;

		while(i < c.length())
		{
			char ch = c.get(i);

			if(ch < 0x0080)
			{
				sOut.write(ch);
			}
			else if(ch < 0x0800)
			{
				sOut.write(0xc0 | (ch >> 6));
				sOut.write(0x80 | (ch & 0x3f));
			}
			// surrogate pair
			else if(ch >= 0xD800 && ch <= 0xDFFF)
			{
				// in error - can only happen, if the Java String class has a
				// bug.
				if(i + 1 >= c.length())
				{
					throw new IllegalStateException("invalid UTF-16 codepoint");
				}
				char W1 = ch;
				ch = c.get(++i);
				char W2 = ch;
				// in error - can only happen, if the Java String class has a
				// bug.
				if(W1 > 0xDBFF)
				{
					throw new IllegalStateException("invalid UTF-16 codepoint");
				}
				int codePoint = (((W1 & 0x03FF) << 10) | (W2 & 0x03FF)) + 0x10000;
				sOut.write(0xf0 | (codePoint >> 18));
				sOut.write(0x80 | ((codePoint >> 12) & 0x3F));
				sOut.write(0x80 | ((codePoint >> 6) & 0x3F));
				sOut.write(0x80 | (codePoint & 0x3F));
			}
			else
			{
				sOut.write(0xe0 | (ch >> 12));
				sOut.write(0x80 | ((ch >> 6) & 0x3F));
				sOut.write(0x80 | (ch & 0x3F));
			}

			i++;
		}
	}
	
	
    public static boolean isNullOrEmpty(byte[] array)
    {
        return null == array || array.length < 1;
    }


	public static boolean compareConstantTime(CByteArray a, int aOffset, int length, CByteArray b, int bOffset)
	{
		if((a == null) || (b == null))
		{
			return false;
		}

		int x = 0;
		for(int i=0; i<length; i++)
		{
			x |= (a.get(i + aOffset) ^ b.get(i + bOffset));
		}
		
		return (x == 0);
	}
	
	
	@Deprecated // leaks secrets in byte[]
	public static byte[] charsToBytes(OpaqueChars input, Charset charset)
	{
		if(input == null)
		{
			return null;
		}
		
		CCharArray cs = input.getChars();
		try
		{
			CByteArray b = charsToBytes(cs, charset);
			try
			{
				return b.toByteArray();
			}
			finally
			{
				b.zero();
			}
		}
		finally
		{
			cs.zero();
		}
	}
	
	
	public static CByteArray charsToBytes(CCharArray a)
	{
		if(a == null)
		{
			return null;
		}
		
		int sz = a.length();
		CByteArray b = new CByteArray(sz * CCharArray.BYTES_PER_CHAR);
		for(int i=0; i<sz; i++)
		{
			char c = a.get(i);
			b.buffer.putChar(i * CCharArray.BYTES_PER_CHAR, c);
		}
		return b;
	}
	
	
	public static CCharArray bytesToChars(CByteArray b)
	{
		if(b == null)
		{
			return null;
		}
		
		int sz = b.length() / 2;
		if((sz * 2) != b.length())
		{
			throw new IllegalArgumentException("length must be even: " + b.length());
		}
		
		CCharArray a = new CCharArray(sz);
		for(int i=0; i<sz; i++)
		{
			char c = b.buffer.getChar(i * 2);
			a.set(i, c);
		}
		return a;
	}


	/** 
	 * converts CCharArray into a CByteArray using the specified Charset.
	 * due to limitations of Charset stream encoder which only works with Byte/CharBuffers,
	 * the conversion is made one code point at a time.
	 */
	public static CByteArray charsToBytes(CCharArray chars, Charset charset)
	{
		int len = chars.length();
		CByteArrayOutputStream out = new CByteArrayOutputStream(len * 4);
		CharBuffer cbuf = CharBuffer.allocate(2);
		try
		{
			for(int i=0; i<chars.length(); i++)
			{
				cbuf.clear();
				char c = chars.get(i);
				cbuf.append(c);
				
				if(Character.isHighSurrogate(c))
				{
					if(i + 1 < chars.length())
					{
						char c2 = chars.get(i + 1);
						cbuf.append(c2);
						i++;
					}
				}
				
				ByteBuffer bb = charset.encode(cbuf);
				for(int j=0; j<bb.position(); j++)
				{
					byte b = bb.get(j);
					out.write(b);
					b = 0;
				}
			}
			
			return out.toCByteArray();
		}
		finally
		{
			CKit.close(out);
			cbuf.clear();
			cbuf.append('\u0000');
			cbuf.append('\u0000');
		}
	}
	

	static int codePointAtImpl(char[] a, int index, int limit)
	{
		char c1 = a[index];
		if(Character.isHighSurrogate(c1) && ++index < limit)
		{
			char c2 = a[index];
			if(Character.isLowSurrogate(c2))
			{
				return Character.toCodePoint(c1, c2);
			}
		}
		return c1;
	}
}
