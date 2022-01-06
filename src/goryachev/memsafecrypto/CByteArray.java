// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
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
	
	
	public CByteArray(CByteArray src)
	{
		super(src);
	}
	
	
	public CByteArray(CByteArray src, int offset, int length)
	{
		super(src, offset, length);
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
		if(src == null)
		{
			return null;
		}
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
	
	
	public static CByteArray readOnly(CByteArray src, int offset, int len)
	{
		if(src == null)
		{
			return null;
		}
		
		return src.toReadOnly(offset, len);
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
	
	
	public void copyFrom(byte[] src, int srcPos, int length, int destPos)
	{
		checkWriteable();
		
		for(int i=0; i<length; i++)
		{
			byte v = src[i + srcPos];
			buffer.put(i + destPos, v);
		}
	}
	

	public void copyFrom(CByteArray src, int srcPos, int length, int destPos)
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
	
	
	public void setInt(int index, int value)
	{
		checkWriteable();
		
		buffer.putInt(index, value);
	}
	
	
	public int getInt(int index)
	{
		return buffer.getInt(index);
	}
}
