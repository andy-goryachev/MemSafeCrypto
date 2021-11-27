// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.memsafecrypto.util.DirectArrayBase;


/**
 * Zeroable byte[] equivalent based on DirectByteBuffer.
 */
public final class CByteArray
	extends DirectArrayBase
{
	public CByteArray(int capacity)
	{
		super(capacity);
	}
	
	
	public CByteArray(CByteArray b)
	{
		super(b);
	}
	
	
	public int length()
	{
		return sizeInBytes();
	}
	
	
	public byte get(int index)
	{
		return buffer.get(index);
	}
	
	
	public byte read()
	{
		return buffer.get();
	}
	
	
	public void set(int index, byte value)
	{
		checkWriteable();
		
		buffer.put(index, value);
	}
	
	
	public void set(int index, byte[] src, int offset, int len)
	{
		checkWriteable();
		
		buffer.position(index);
		buffer.put(src, offset, len);
	}
	
	
	public CByteArray toReadOnly()
	{
		CByteArray b = new CByteArray(this);
		b.setReadOnly();
		return b;
	}
	
	
	public CByteArray toReadOnly(int offset, int length)
	{
		CByteArray b = new CByteArray(length);
		b.copyBytes(0, this, offset, length);
		b.setReadOnly();
		return b;
	}
	
	
	public static CByteArray readOnly(byte[] src)
	{
		return readOnly(src, 0, src.length);
	}
	
	
	public static CByteArray readOnly(byte[] src, int offset, int len)
	{
		CByteArray b = new CByteArray(len);
		b.set(0, src, offset, len);
		b.setReadOnly();
		return b;
	}
	
	
	public static CByteArray readOnly(CByteArray src)
	{
		if(src == null)
		{
			return null;
		}
		
		CByteArray b = new CByteArray(src);
		b.setReadOnly();
		return b;
	}
	
	
	public void write(int b)
	{
		checkWriteable();
		
		buffer.put((byte)b);
	}
	
	
	public void write(byte[] bytes)
	{
		checkWriteable();
		
		buffer.put(bytes);
	}
	
	
	public void write(CByteArray b)
	{
		write(b, 0, b.length());
	}
	
	
	public void write(CByteArray b, int off, int len)
	{
		checkWriteable();
		
		for(int i=off; i<len; i++)
		{
			byte v = b.get(i);
			buffer.put(v);
		}
	}
	
	
	public char readChar(int ix)
	{
		return buffer.getChar(ix);
	}
	
	
	public void fill(byte value)
	{
		checkWriteable();
		
		int len = length();
		for(int i=0; i<len; i++)
		{
			buffer.put(i, value);
		}
	}
	
	
	public void copy(int destPos, byte[] src, int srcPos, int length)
	{
		checkWriteable();
		
		for(int i=0; i<length; i++)
		{
			byte v = src[i + srcPos];
			buffer.put(i + destPos, v);
		}
	}
	

	public void copy(int destPos, CByteArray src, int srcPos, int length)
	{
		checkWriteable();
		
		for(int i=0; i<length; i++)
		{
			byte v = src.get(i + srcPos);
			buffer.put(i + destPos, v);
		}
	}
	
	
	public byte[] toByteArray()
	{
		int len = length();
		byte[] rv = new byte[len];
		for(int i=0; i<len; i++)
		{
			byte b = buffer.get(i);
			rv[i] = b;
		}
		return rv;
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


	public boolean sameContentAs(CByteArray b)
	{
		if(b == null)
		{
			return false;
		}
		
		int sz = sizeInBytes();
		if(sz != b.sizeInBytes())
		{
			return false;
		}
		
		for(int i=0; i<sz; i++)
		{
			byte c = get(i);
			if(c != b.get(i))
			{
				return false;
			}
		}
		return true;
	}
	
	
	public void xor(int index, byte value)
	{
		checkWriteable();
		
		byte v = buffer.get(index);
		v ^= value;
		buffer.put(index, v);
	}
	
	
	public byte incrementAndGet(int index)
	{
		checkWriteable();
		
		byte v = buffer.get(index);
		v++;
		buffer.put(index, v);
		return v;
	}
}
