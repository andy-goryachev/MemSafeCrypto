// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;


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
	
	
	public byte[] toByteArray()
	{
		int sz = length();
		byte[] rv = new byte[sz];
		for(int i=0; i<sz; i++)
		{
			byte b = buffer.get(i);
			rv[i] = b;
		}
		return rv;
	}
}
